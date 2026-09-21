package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cortezaproject/corteza/server/pkg/id"
	"github.com/cortezaproject/corteza/server/pkg/options"
	"github.com/cortezaproject/corteza/server/store"
	"github.com/cortezaproject/corteza/server/store/adapters/rdbms/drivers/sqlite"
	"github.com/cortezaproject/corteza/server/system/types"
	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	oauth2models "github.com/go-oauth2/oauth2/v4/models"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var (
	exchangeTestIDInit sync.Once
)

func initExchangeTestIDs() {
	exchangeTestIDInit.Do(func() {
		id.Init(context.Background())
	})
}

type exchangeFixture struct {
	t      *testing.T
	ctx    context.Context
	store  store.Storer
	mgr    *Manager
	client *types.AuthClient
}

func newExchangeFixture(t *testing.T) *exchangeFixture {
	initExchangeTestIDs()

	var (
		ctx = context.Background()
	)

	// dedicated file-backed SQLite DB per test; busy timeout makes concurrent
	// writers queue on the database lock instead of failing with SQLITE_BUSY,
	// which lets the atomic single-use claim be exercised under contention
	dsn := "sqlite3+alt://file:" + filepath.Join(
		os.TempDir(),
		"corteza-oauth2-exchange-"+strconv.FormatUint(id.Next(), 10)+".db",
	) + "?_busy_timeout=15000"

	s, err := sqlite.Connect(ctx, dsn)
	require.NoError(t, err)

	require.NoError(t, store.Upgrade(ctx, zap.NewNop(), s))

	c := &types.AuthClient{
		ID:          id.Next(),
		Handle:      "test-client-" + strconv.FormatUint(id.Next(), 10),
		Secret:      "correct-horse-battery-staple",
		RedirectURI: "https://example.tld/cb",
		CreatedAt:   time.Now(),
	}
	require.NoError(t, store.CreateAuthClient(ctx, s, c))

	m := NewManager(
		options.AuthOpt{
			AccessTokenLifetime:  time.Hour * 2,
			RefreshTokenLifetime: time.Hour * 24 * 3,
		},
		zap.NewNop(),
		s,
		NewClientStore(s, nil),
	)

	return &exchangeFixture{
		t:      t,
		ctx:    ctx,
		store:  s,
		mgr:    m,
		client: c,
	}
}

func (f *exchangeFixture) clientID() string {
	return strconv.FormatUint(f.client.ID, 10)
}

// issueCode runs the regular authorization endpoint step that persists the
// authorization code row
func (f *exchangeFixture) issueCode(userID, scope, redirectURI string, challenge oauth2.CodeChallengeMethod, codeChallenge string) oauth2.TokenInfo {
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:            f.clientID(),
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: challenge,
	}

	ti, err := f.mgr.GenerateAuthToken(f.ctx, oauth2.Code, tgr)
	require.NoError(f.t, err)
	require.NotEmpty(f.t, ti.GetCode())

	return ti
}

func (f *exchangeFixture) exchangeTgr(code, redirectURI, verifier string) *oauth2.TokenGenerateRequest {
	return &oauth2.TokenGenerateRequest{
		ClientID:     f.clientID(),
		ClientSecret: f.client.Secret,
		RedirectURI:  redirectURI,
		Code:         code,
		CodeVerifier: verifier,
	}
}

func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
}

func noopIssue() AuthorizationCodeIssueFn {
	return func(_ context.Context, _ oauth2.TokenInfo) error { return nil }
}

func TestExchangeAuthorizationCodeSuccess(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	const userID = "42"

	code := f.issueCode(userID, "api profile openid", "https://example.tld/cb", "", "")

	var (
		issueCalls int
		issuedTI   oauth2.TokenInfo
	)

	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		func(_ context.Context, in oauth2.TokenInfo) error {
			issueCalls++
			issuedTI = in
			return nil
		},
	)
	req.NoError(err)
	req.Equal(1, issueCalls)
	req.NotEmpty(ti.GetAccess())
	req.NotEmpty(ti.GetRefresh())
	req.Equal(userID, ti.GetUserID())
	req.Equal("api profile openid", ti.GetScope())
	req.Equal(ti.GetAccess(), issuedTI.GetAccess())

	// code row must no longer be resolvable by code — it is retired
	_, err = store.LookupAuthOa2tokenByCode(f.ctx, f.store, code.GetCode())
	req.Error(err)

	// but the row must exist as access/refresh token row with raw values
	accessRow, err := store.LookupAuthOa2tokenByAccess(f.ctx, f.store, ti.GetAccess())
	req.NoError(err)
	req.NotNil(accessRow)
	req.Empty(accessRow.Code)
	req.Equal(ti.GetRefresh(), accessRow.Refresh)

	_, err = store.LookupAuthOa2tokenByRefresh(f.ctx, f.store, ti.GetRefresh())
	req.NoError(err)

	// confirmed-client relation was upserted in the same boundary
	acc, err := store.LookupAuthConfirmedClientByUserIDClientID(f.ctx, f.store, 42, f.client.ID)
	req.NoError(err)
	req.NotNil(acc)

	// the code can never be exchanged again — replay, restart or GC
	_, err = f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)

	// no second token set exists — the code row was converted, not duplicated
	set, _, err := store.SearchAuthOa2tokens(f.ctx, f.store, types.AuthOa2tokenFilter{})
	req.NoError(err)
	req.Len(set, 1)
}

func TestExchangePKCEMustNotConsumeCode(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	const (
		verifier        = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		wrongVerifier   = "this-is-not-the-right-verifier"
	)

	code := f.issueCode(
		"42",
		"api",
		"https://example.tld/cb",
		oauth2.CodeChallengeS256,
		pkceS256Challenge(verifier),
	)

	// wrong PKCE verifier must reject the request but NOT retire the code
	_, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", wrongVerifier),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)

	// missing verifier rejects too but must still not consume the code
	_, err = f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)

	// code row is still there
	row, err := store.LookupAuthOa2tokenByCode(f.ctx, f.store, code.GetCode())
	req.NoError(err)
	req.NotNil(row)

	// legitimate client with the correct verifier still gets its tokens
	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", verifier),
		noopIssue(),
	)
	req.NoError(err)
	req.NotEmpty(ti.GetAccess())

	// and now even the correct verifier can not exchange the code twice
	_, err = f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", verifier),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)
}

func TestExchangePKCEPlain(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	const verifier = "plain-verifier-value"

	code := f.issueCode("7", "api", "https://example.tld/cb", oauth2.CodeChallengePlain, verifier)

	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", verifier),
		noopIssue(),
	)
	req.NoError(err)
	req.NotEmpty(ti.GetAccess())
}

func TestExchangeInvalidClientAndRedirectDoNotConsumeCode(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	code := f.issueCode("42", "api", "https://example.tld/cb", "", "")

	// wrong client secret
	tgr := f.exchangeTgr(code.GetCode(), "https://example.tld/cb", "")
	tgr.ClientSecret = "totally-wrong"
	_, err := f.mgr.ExchangeAuthorizationCode(f.ctx, tgr, noopIssue())
	req.ErrorIs(err, oauth2errors.ErrInvalidClient)

	// wrong redirect URI
	_, err = f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/other", ""),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidRedirectURI)

	// wrong client ID — code belongs to another client
	// create the other client first so the error is a grant error, not a lookup error
	other := &types.AuthClient{ID: 99999999, Secret: "other-secret", CreatedAt: time.Now()}
	req.NoError(store.CreateAuthClient(f.ctx, f.store, other))

	tgr = f.exchangeTgr(code.GetCode(), "https://example.tld/cb", "")
	tgr.ClientID = "99999999"
	tgr.ClientSecret = "other-secret"
	_, err = f.mgr.ExchangeAuthorizationCode(f.ctx, tgr, noopIssue())
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)

	// code survives all invalid attempts and exchanges successfully
	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		noopIssue(),
	)
	req.NoError(err)
	req.NotEmpty(ti.GetAccess())
}

func TestExchangeExpiredCode(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	// codes for this fixture live only 200ms
	f.mgr.SetAuthorizeCodeExp(200 * time.Millisecond)

	code := f.issueCode("42", "api", "https://example.tld/cb", "", "")

	time.Sleep(300 * time.Millisecond)

	_, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		noopIssue(),
	)
	req.ErrorIs(err, oauth2errors.ErrInvalidGrant)

	// expired code is not considered exchanged — expired-code cleanup
	// behavior is unchanged
	row, err := store.LookupAuthOa2tokenByCode(f.ctx, f.store, code.GetCode())
	req.NoError(err)
	req.NotNil(row)
}

func TestExchangeIssueFailureKeepsCode(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)

		boom = errors.New("user service down")
	)

	code := f.issueCode("42", "api", "https://example.tld/cb", "", "")

	// issue callback (user load / JWT / OIDC) fails BEFORE the code is claimed
	_, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		func(_ context.Context, _ oauth2.TokenInfo) error { return boom },
	)
	req.ErrorIs(err, boom)

	// code is untouched and no access/refresh token row exists
	// (note: the confirmed-client relation is upserted at code-issuance time
	// by the regular authorization flow, same as before this change)
	set, _, err := store.SearchAuthOa2tokens(f.ctx, f.store, types.AuthOa2tokenFilter{})
	req.NoError(err)
	req.Len(set, 1)
	req.Equal(code.GetCode(), set[0].Code)
	req.Empty(set[0].Access)
	req.Empty(set[0].Refresh)

	_, err = store.LookupAuthOa2tokenByAccess(f.ctx, f.store, "anything")
	req.Error(err)

	// once the fault is gone, the original request can be safely retried
	var issued bool
	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		func(_ context.Context, _ oauth2.TokenInfo) error { issued = true; return nil },
	)
	req.NoError(err)
	req.True(issued)
	req.NotEmpty(ti.GetAccess())
}

func TestExchangeConcurrentSingleWinner(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)

		concurrency = 32
		wg          sync.WaitGroup

		successes int
		grants    int
		other     int

		mu sync.Mutex
	)

	code := f.issueCode("42", "api", "https://example.tld/cb", "", "")

	// gate goroutines to maximize contention
	start := make(chan struct{})

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-start

			ti, err := f.mgr.ExchangeAuthorizationCode(
				f.ctx,
				f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
				noopIssue(),
			)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				successes++
				if ti.GetAccess() != "" {
					grants++
				}
			case errors.Is(err, oauth2errors.ErrInvalidGrant):
				grants++
			default:
				other++
				req.NoError(err)
			}
		}()
	}

	close(start)
	wg.Wait()

	req.Equal(1, successes, "exactly one request must receive tokens")
	req.Equal(concurrency, grants, "every request must succeed or receive a stable invalid_grant")
	req.Equal(0, other)

	// exactly one token row, code permanently retired
	set, _, err := store.SearchAuthOa2tokens(f.ctx, f.store, types.AuthOa2tokenFilter{})
	req.NoError(err)
	req.Len(set, 1)
	req.Empty(set[0].Code)
	req.NotEmpty(set[0].Access)
	req.NotEmpty(set[0].Refresh)

	_, err = store.LookupAuthOa2tokenByCode(f.ctx, f.store, code.GetCode())
	req.Error(err)
}

func TestExchangeRefreshFlowStillWorks(t *testing.T) {
	var (
		req = require.New(t)
		f   = newExchangeFixture(t)
	)

	code := f.issueCode("42", "api", "https://example.tld/cb", "", "")

	ti, err := f.mgr.ExchangeAuthorizationCode(
		f.ctx,
		f.exchangeTgr(code.GetCode(), "https://example.tld/cb", ""),
		noopIssue(),
	)
	req.NoError(err)

	// go-oauth2 refresh flow is unchanged and must keep working
	refreshed, err := f.mgr.RefreshAccessToken(f.ctx, &oauth2.TokenGenerateRequest{
		ClientID:     f.clientID(),
		ClientSecret: f.client.Secret,
		Refresh:      ti.GetRefresh(),
	})
	req.NoError(err)
	req.NotEmpty(refreshed.GetAccess())
	req.NotEmpty(refreshed.GetRefresh())
	req.NotEqual(ti.GetAccess(), refreshed.GetAccess())
}

func TestValidateCodeChallenge(t *testing.T) {
	var (
		req = require.New(t)
		ti  = &oauth2models.Token{}
	)

	// public code without challenge and no verifier — nothing to validate
	req.NoError(validateCodeChallenge(ti, ""))

	ti.SetCodeChallengeMethod(oauth2.CodeChallengeS256)
	ti.SetCodeChallenge(pkceS256Challenge("verifier"))
	req.NoError(validateCodeChallenge(ti, "verifier"))
	req.ErrorIs(validateCodeChallenge(ti, "nope"), oauth2errors.ErrInvalidCodeChallenge)
	req.ErrorIs(validateCodeChallenge(ti, ""), oauth2errors.ErrMissingCodeVerifier)

	// plain challenge method
	ti.SetCodeChallengeMethod(oauth2.CodeChallengePlain)
	ti.SetCodeChallenge("abc")
	req.NoError(validateCodeChallenge(ti, "abc"))
	req.ErrorIs(validateCodeChallenge(ti, ""), oauth2errors.ErrMissingCodeVerifier)

	// verifier sent for a code without challenge
	empty := &oauth2models.Token{}
	req.ErrorIs(validateCodeChallenge(empty, "abc"), oauth2errors.ErrMissingCodeVerifier)
}
