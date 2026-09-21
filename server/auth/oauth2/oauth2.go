package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cortezaproject/corteza/server/pkg/handle"
	"github.com/cortezaproject/corteza/server/pkg/logger"
	"github.com/cortezaproject/corteza/server/pkg/options"
	"github.com/cortezaproject/corteza/server/pkg/payload"
	"github.com/cortezaproject/corteza/server/store"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"go.uber.org/zap"
)

const (
	RedirectUriSeparator = " "
)

// Manager wraps go-oauth2 manager and adds Corteza's hardened,
// database-enforced single-use authorization-code exchange
type Manager struct {
	*manage.Manager

	store store.Storer

	// token & client stores mapped onto the underlying manager
	tokens  *tokenStore
	clients oauth2.ClientStore

	// token generator used when issuing access/refresh tokens
	accessGen oauth2.AccessGenerate

	// configuration for authorization-code grant tokens
	codeTokenCfg *manage.Config

	// redirect URI validation handler, reused by the hardened exchange
	validateURI manage.ValidateURIHandler
}

func NewManager(opt options.AuthOpt, log *zap.Logger, s store.Storer, cs oauth2.ClientStore) *Manager {
	manager := manage.NewDefaultManager()

	// Here we are cloning the internal package variable as I do not think
	// it is sane to overwrite it directly.
	cfg := *manage.DefaultAuthorizeCodeTokenCfg
	cfg.AccessTokenExp = opt.AccessTokenLifetime
	cfg.RefreshTokenExp = opt.RefreshTokenLifetime

	manager.SetAuthorizeCodeTokenCfg(&cfg)

	// token store
	ts := NewTokenStore(s)
	manager.MapTokenStorage(ts)
	manager.MapClientStorage(cs)
	// Change the default config for it to update refresh token timestamps
	// else the refresh token timestamp remains the same
	//
	// @note do this so we don't change the default `manage` package var
	rcfg := *manage.DefaultRefreshTokenCfg
	rcfg.IsResetRefreshTime = true
	manager.SetRefreshTokenCfg(&rcfg)

	validateURI := newValidateURIHandler(log)
	manager.SetValidateURIHandler(validateURI)

	return &Manager{
		Manager:      manager,
		store:        s,
		tokens:       ts,
		clients:      cs,
		accessGen:    generates.NewAccessGenerate(),
		codeTokenCfg: &cfg,
		validateURI:  validateURI,
	}
}

func newValidateURIHandler(log *zap.Logger) manage.ValidateURIHandler {
	return func(baseURI, redirectURI string) (err error) {
		if baseURI == "" {
			log.Debug(
				"redirect URI check for client is disabled (empty validation list)",
				zap.String("sent", redirectURI),
			)

			return nil
		}

		var (
			valid = strings.Split(baseURI, RedirectUriSeparator)
		)

		log.Debug(
			"matching redirectURI",
			zap.String("sent", redirectURI),
			zap.Strings("valid", valid),
		)

		for _, baseURI = range valid {
			if strings.HasPrefix(redirectURI, baseURI) {
				return nil
			}
		}

		return errors.ErrInvalidRedirectURI
	}
}

// Server wraps go-oauth2 server and exposes the hardened
// authorization-code exchange endpoint
type Server struct {
	*server.Server

	mgr *Manager
}

func NewServer(manager *Manager) *Server {
	srv := server.NewServer(&server.Config{
		TokenType:             "Bearer",
		AllowGetAccessRequest: false,
		AllowedResponseTypes: []oauth2.ResponseType{
			oauth2.Code,
		},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.Refreshing,
			oauth2.ClientCredentials,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
	}, manager)

	srv.ClientInfoHandler = func(r *http.Request) (clientID, clientSecret string, err error) {
		// check in basic handler first
		clientID, clientSecret, err = server.ClientBasicHandler(r)

		if clientID == "" && clientSecret == "" {
			//error or no error, when ID & secret are empty,
			// check the form handler
			clientID, clientSecret, err = server.ClientFormHandler(r)
		}

		// just in case, when client's handle is used instead of the ID
		// preload it here
		if id := payload.ParseUint64(clientID); id == 0 && handle.IsValid(clientID) {
			var client oauth2.ClientInfo
			client, err = manager.GetClient(r.Context(), clientID)
			if err != nil {
				err = fmt.Errorf("could not resolve client info: %v", err)
				return
			}

			clientID = client.GetID()
		}

		return
	}

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		return errors.NewResponse(err, 500)
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		msg := re.Description
		if msg == "" {
			msg = re.Error.Error()
		}

		logger.Default().Warn(msg)
	})

	return &Server{Server: srv, mgr: manager}
}

// ExchangeAuthorizationCode performs the hardened, single-use authorization
// code exchange.
//
// It mirrors the preamble of go-oauth2's GetAccessToken for the
// authorization-code grant (grant-type & client authorization checks)
// and delegates the validated, atomic exchange to the manager.
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, tgr *oauth2.TokenGenerateRequest, issue AuthorizationCodeIssueFn) (ti oauth2.TokenInfo, err error) {
	if allowed := s.CheckGrantType(oauth2.AuthorizationCode); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, oauth2.AuthorizationCode)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	return s.mgr.ExchangeAuthorizationCode(ctx, tgr, issue)
}
