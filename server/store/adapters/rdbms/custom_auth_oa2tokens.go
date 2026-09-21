package rdbms

import (
	"context"
	"database/sql"
	"time"

	"github.com/cortezaproject/corteza/server/system/types"
	"github.com/doug-martin/goqu/v9"
)

func (s Store) DeleteExpiredAuthOA2Tokens(ctx context.Context) error {
	return s.Exec(ctx, authOa2tokenDeleteQuery(s.Dialect.GOQU(), goqu.C("expires_at").Lt(time.Now())))
}

// ClaimAuthOA2AuthorizationCode atomically retires the authorization-code row
// and overwrites it with the issued access/refresh token row in one UPDATE.
//
// The conditional predicate (code = ?) together with RowsAffected is the
// database-enforced single-use constraint: when two requests (from different
// goroutines or different server instances) race for the same code, the row
// lock serializes the statements and exactly one UPDATE matches the row.
// The losing statement affects 0 rows and returns false, which the caller
// maps to a stable OAuth2 invalid_grant response.
//
// Safe to run on the store handed over by store.Tx; when executed inside a
// transaction the claim is rolled back when the transaction fails.
func (s Store) ClaimAuthOA2AuthorizationCode(ctx context.Context, code string, rr *types.AuthOa2token) (claimed bool, err error) {
	var res sql.Result

	res, err = s.ExecR(ctx, authOa2tokenClaimCodeQuery(s.Dialect.GOQU(), code, rr))
	if err != nil {
		return
	}

	var affected int64
	if affected, err = res.RowsAffected(); err != nil {
		return
	}

	// at most one row ever carries a given (non-empty) code
	return affected > 0, nil
}

// authOa2tokenClaimCodeQuery builds the atomic statement that converts
// the authorization-code row into the issued-token row
func authOa2tokenClaimCodeQuery(d goqu.DialectWrapper, code string, rr *types.AuthOa2token) *goqu.UpdateDataset {
	// code is retired (set to empty string) in the same statement that
	// writes the token, so the row can never be matched by another exchange
	return d.Update(authOa2tokenTable).
		Set(goqu.Record{
			"code":        "",
			"access":      rr.Access,
			"refresh":     rr.Refresh,
			"data":        rr.Data,
			"remote_addr": rr.RemoteAddr,
			"user_agent":  rr.UserAgent,
			"rel_client":  rr.ClientID,
			"rel_user":    rr.UserID,
			"created_at":  rr.CreatedAt,
			"expires_at":  rr.ExpiresAt,
		}).
		Where(goqu.C("code").Eq(code))
}

func (s Store) DeleteAuthOA2TokenByCode(ctx context.Context, code string) error {
	return s.Exec(ctx, authOa2tokenDeleteQuery(s.Dialect.GOQU(), goqu.C("code").Eq(code)))
}

func (s Store) DeleteAuthOA2TokenByAccess(ctx context.Context, access string) error {
	return s.Exec(ctx, authOa2tokenDeleteQuery(s.Dialect.GOQU(), goqu.C("access").Eq(access)))
}

func (s Store) DeleteAuthOA2TokenByRefresh(ctx context.Context, refresh string) error {
	return s.Exec(ctx, authOa2tokenDeleteQuery(s.Dialect.GOQU(), goqu.C("refresh").Eq(refresh)))
}

func (s Store) DeleteAuthOA2TokenByUserID(ctx context.Context, userID uint64) error {
	return s.Exec(ctx, authOa2tokenDeleteQuery(s.Dialect.GOQU(), goqu.C("rel_user").Eq(userID)))
}
