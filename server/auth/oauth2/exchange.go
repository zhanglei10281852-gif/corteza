package oauth2

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cortezaproject/corteza/server/pkg/auth"
	"github.com/cortezaproject/corteza/server/store"
	"github.com/cortezaproject/corteza/server/system/types"
	"github.com/go-oauth2/oauth2/v4"
	oa2err "github.com/go-oauth2/oauth2/v4/errors"
	oauth2models "github.com/go-oauth2/oauth2/v4/models"
)

type (
	// AuthorizationCodeIssueFn is invoked by ExchangeAuthorizationCode
	// BEFORE the authorization code is claimed (retired).
	//
	// Everything required to turn the raw access token into verifiable
	// credentials must happen here: user (identity) validation, JWT
	// signing and optional OIDC id_token generation.
	//
	// When the function returns an error, no state has been changed: the
	// authorization code remains valid and can be safely exchanged again,
	// and no orphan token or half-written confirmed-client relation is left.
	AuthorizationCodeIssueFn func(ctx context.Context, ti oauth2.TokenInfo) error

	// authCodeClaimer is implemented by store backends that can atomically
	// retire an authorization code and replace it with the issued token row
	authCodeClaimer interface {
		ClaimAuthOA2AuthorizationCode(ctx context.Context, code string, rr *types.AuthOa2token) (bool, error)
	}
)

// ExchangeAuthorizationCode exchanges an authorization code for access and
// refresh tokens in one database-enforced single-use commit.
//
// Order of operations:
//
//  1. read-only validation — client credentials, redirect URI, code
//     existence/expiry/owner/redirect URI and PKCE code_verifier — nothing
//     touches the code row, so a request with a wrong PKCE verifier can never
//     retire the legitimate client's code;
//
//  2. credential preparation — raw access/refresh token generation, token
//     info serialization and the issue callback (user validation, JWT and
//     optional OIDC id_token signing) — no state is changed, so every failure
//     at this stage leaves the code intact and exchangeable;
//
//  3. atomic commit — a single conditional UPDATE retires the code and writes
//     the token row; only one concurrent request (same goroutine, another
//     goroutine or another server instance) can win the claim, every other
//     request deterministically receives invalid_grant; the winner upserts
//     the confirmed-client relation in the same transaction boundary;
//
//  4. any failure before/at the commit leaves no verifiable orphan token and
//     never permanently consumes a code that never yielded credentials — on
//     transactional stores the whole boundary rolls back, and on stores
//     without transaction support (SQLite) the only operation before the
//     claim was credential preparation, which never touches the database.
//     After the fault is gone the original request can be safely retried.
//
// Once committed, the code is permanently retired — it can not be exchanged
// again after a process restart, garbage collection or HTTP response replay.
// Response write failures happen after the commit and must never reopen the
// code.
func (m *Manager) ExchangeAuthorizationCode(ctx context.Context, tgr *oauth2.TokenGenerateRequest, issue AuthorizationCodeIssueFn) (_ oauth2.TokenInfo, err error) {
	if issue == nil {
		return nil, fmt.Errorf("authorization code issue function not configured")
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}

	// ---- 1a. authenticate client (mirrors go-oauth2 manager) -------------
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	}

	if cliPass, ok := cli.(oauth2.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(tgr.ClientSecret) {
			return nil, oa2err.ErrInvalidClient
		}
	} else if len(cli.GetSecret()) > 0 && tgr.ClientSecret != cli.GetSecret() {
		return nil, oa2err.ErrInvalidClient
	}

	// ---- 1b. validate redirect URI BEFORE touching the code --------------
	if tgr.RedirectURI != "" {
		if err = m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	// ---- 1c. load and validate the code BEFORE any state change ----------
	codeTI, err := m.tokens.GetByCode(ctx, tgr.Code)
	if err != nil {
		// missing/consumed code is an invalid grant; underlying store
		// errors must propagate (and surface as server errors) unchanged
		if errors.Is(err, oa2err.ErrInvalidAuthorizeCode) {
			return nil, oa2err.ErrInvalidGrant
		}

		return nil, err
	} else if codeTI == nil {
		return nil, oa2err.ErrInvalidGrant
	}

	if codeTI.GetCode() != tgr.Code {
		return nil, oa2err.ErrInvalidGrant
	}

	if codeTI.GetCodeCreateAt().Add(codeTI.GetCodeExpiresIn()).Before(time.Now()) {
		return nil, oa2err.ErrInvalidGrant
	}

	if codeTI.GetClientID() != tgr.ClientID {
		return nil, oa2err.ErrInvalidGrant
	}

	if codeURI := codeTI.GetRedirectURI(); codeURI != "" && codeURI != tgr.RedirectURI {
		return nil, oa2err.ErrInvalidGrant
	}

	// ---- 1d. PKCE, strictly before the code is retired -------------------
	//
	// A wrong or missing code_verifier must invalidate the request, not the
	// legitimate client's code.
	if err = validateCodeChallenge(codeTI, tgr.CodeVerifier); err != nil {
		return nil, oa2err.ErrInvalidGrant
	}

	// ---- 2. prepare the new token (no state is changed here) -------------
	var (
		clientID uint64
		userID   uint64
	)

	if clientID, err = strconv.ParseUint(tgr.ClientID, 10, 64); err != nil {
		return nil, fmt.Errorf("could not parse client ID from token request: %w", err)
	}

	if userID, _ = auth.ExtractFromSubClaim(codeTI.GetUserID()); userID == 0 {
		return nil, fmt.Errorf("could not parse user ID from authorization code")
	}

	ti := oauth2models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(codeTI.GetUserID())
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(codeTI.GetScope())

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	aexp := m.codeTokenCfg.AccessTokenExp
	// code may carry a preconfigured access-token expiration
	if exp := codeTI.GetAccessExpiresIn(); exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)

	if m.codeTokenCfg.IsGenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(m.codeTokenCfg.RefreshTokenExp)
	}

	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    codeTI.GetUserID(),
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	av, rv, err := m.accessGen.Token(ctx, td, m.codeTokenCfg.IsGenerateRefresh)
	if err != nil {
		return nil, err
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	// token row + confirmed-client relation; same projection as the regular
	// token store create (raw access/refresh values are persisted here)
	oa2t, acc, err := makeAuthStructs(ctx, userID, clientID, ti, ti.GetCodeExpiresIn())
	if err != nil {
		return nil, err
	}

	// ---- 3. user validation, JWT and OIDC signing (no state change) ------
	//
	// This runs BEFORE the code is claimed: if the user can not be loaded or
	// a credential can not be signed, the code is neither retired nor is an
	// orphan token left behind, so the original request can be safely retried.
	if err = issue(ctx, ti); err != nil {
		return nil, err
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}

	// ---- 4. database-enforced single-use commit --------------------------
	var claimed bool

	err = store.Tx(ctx, m.store, func(ctx context.Context, tx store.Storer) error {
		claimer, ok := tx.(authCodeClaimer)
		if !ok {
			return fmt.Errorf("store backend does not support atomic authorization code exchange")
		}

		// Atomic claim: code retirement + token row in a single statement.
		// Exactly one racing request (even across instances) can affect the
		// row and win the commit.
		claimed, err = claimer.ClaimAuthOA2AuthorizationCode(ctx, tgr.Code, oa2t)
		if err != nil {
			return err
		}

		if !claimed {
			// Code was already (or concurrently, in another instance)
			// exchanged — stable invalid_grant, no second token set.
			return nil
		}

		if err = store.UpsertAuthConfirmedClient(ctx, tx, acc); err != nil {
			return err
		}

		// never commit an exchange whose request was abandoned
		return ctx.Err()
	})

	if err != nil {
		return nil, err
	}

	if !claimed {
		return nil, oa2err.ErrInvalidGrant
	}

	return ti, nil
}

// validateCodeChallenge mirrors go-oauth2 manager's PKCE validation but it is
// invoked BEFORE the authorization code is retired
func validateCodeChallenge(ti oauth2.TokenInfo, verifier string) error {
	challenge := ti.GetCodeChallenge()

	// public client without PKCE and no verifier — nothing to validate
	if challenge == "" && verifier == "" {
		return nil
	}

	if challenge == "" || verifier == "" {
		return oa2err.ErrMissingCodeVerifier
	}

	method := ti.GetCodeChallengeMethod()
	if method.String() == "" {
		method = oauth2.CodeChallengePlain
	}

	if !method.Validate(challenge, verifier) {
		return oa2err.ErrInvalidCodeChallenge
	}

	return nil
}
