package dal

import (
	"context"
	"errors"
	"testing"

	"github.com/cortezaproject/corteza/server/pkg/filter"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type (
	// trackingIter wraps an in-memory buffer and counts Close invocations so the
	// resource tree ownership and teardown behavior can be asserted.
	trackingIter struct {
		*inmemBuffer

		closed   int
		closeErr error
	}

	// fakeTestConn implements just enough of Connection to drive a Datasource
	// step in unit tests; the Search hook controls what the step receives.
	fakeTestConn struct {
		Connection

		search func(m *Model) (Iterator, error)
	}
)

func newTrackingIter(closeErr ...error) *trackingIter {
	t := &trackingIter{inmemBuffer: InMemoryBuffer()}
	if len(closeErr) > 0 {
		t.closeErr = closeErr[0]
	}
	return t
}

func (t *trackingIter) Close() error {
	t.closed++
	return t.closeErr
}

func (f fakeTestConn) Search(_ context.Context, m *Model, _ filter.Filter) (Iterator, error) {
	return f.search(m)
}

func testSvc(t *testing.T) *service {
	svc, err := New(zap.NewNop(), false)
	require.NoError(t, err)
	return svc
}

// testDatasource prepares a Datasource step bound to a fake connection that
// returns the provided iterator/error from Search.
func testDatasource(ident string, it Iterator, searchErr error) *Datasource {
	ds := &Datasource{
		Ident: ident,
		OutAttributes: saToMapping(simpleAttribute{
			ident:   "id",
			primary: true,
			t:       TypeID{},
		}),
	}

	conn := fakeTestConn{
		search: func(_ *Model) (Iterator, error) {
			return it, searchErr
		},
	}

	ds.model = &Model{Ident: ident}
	ds.connection = MakeConnection(1, conn, ConnectionParams{}, ConnectionConfig{})
	return ds
}

func linkedJoin(left, right PipelineStep, on JoinPredicate) *Join {
	j := &Join{
		Ident:    "jn",
		RelLeft:  left.Identifier(),
		RelRight: right.Identifier(),
		relLeft:  left,
		relRight: right,
		On:       on,
	}
	return j
}

func linkedLink(left, right PipelineStep, on LinkPredicate) *Link {
	l := &Link{
		Ident:    "lnk",
		RelLeft:  left.Identifier(),
		RelRight: right.Identifier(),
		relLeft:  left,
		relRight: right,
		On:       on,
	}
	return l
}

// // // // // // // // // // // // // // // // // // // // // // // // //
// Combiner Close semantics

func TestJoinLeft_CloseIdempotentAndTolerant(t *testing.T) {
	t.Run("closes both sources once and is idempotent", func(t *testing.T) {
		l, r := newTrackingIter(), newTrackingIter()
		xs := &joinLeft{leftSource: l, rightSource: r}

		require.NoError(t, xs.Close())
		require.NoError(t, xs.Close())
		require.Equal(t, 1, l.closed)
		require.Equal(t, 1, r.closed)
	})

	t.Run("continues after a failing child and returns a single error as-is", func(t *testing.T) {
		lErr := errors.New("left boom")
		l, r := newTrackingIter(lErr), newTrackingIter()
		xs := &joinLeft{leftSource: l, rightSource: r}

		err := xs.Close()
		require.ErrorIs(t, err, lErr)
		// the right side must still be released
		require.Equal(t, 1, r.closed)
	})

	t.Run("aggregates both errors in stable order", func(t *testing.T) {
		lErr, rErr := errors.New("left boom"), errors.New("right boom")
		l, r := newTrackingIter(lErr), newTrackingIter(rErr)
		xs := &joinLeft{leftSource: l, rightSource: r}

		err := xs.Close()
		require.Error(t, err)
		require.ErrorIs(t, err, lErr)
		require.ErrorIs(t, err, rErr)
		// left error is reported before the right one
		require.Less(t, indexOf(err.Error(), "left boom"), indexOf(err.Error(), "right boom"))

		// second Close is a no-op even after a failed one
		require.NoError(t, xs.Close())
		require.Equal(t, 1, l.closed)
		require.Equal(t, 1, r.closed)
	})

	t.Run("nil combiner", func(t *testing.T) {
		var xs *joinLeft
		require.NoError(t, xs.Close())
	})
}

func TestLinkLeft_CloseIdempotentAndTolerant(t *testing.T) {
	t.Run("closes both sources once and is idempotent", func(t *testing.T) {
		l, r := newTrackingIter(), newTrackingIter()
		xs := &linkLeft{leftSource: l, rightSource: r}

		require.NoError(t, xs.Close())
		require.NoError(t, xs.Close())
		require.Equal(t, 1, l.closed)
		require.Equal(t, 1, r.closed)
	})

	t.Run("continues after a failing child", func(t *testing.T) {
		rErr := errors.New("right boom")
		l, r := newTrackingIter(), newTrackingIter(rErr)
		xs := &linkLeft{leftSource: l, rightSource: r}

		err := xs.Close()
		require.ErrorIs(t, err, rErr)
		require.Equal(t, 1, l.closed)
	})

	t.Run("nil combiner", func(t *testing.T) {
		var xs *linkLeft
		require.NoError(t, xs.Close())
	})
}

func TestAggregate_CloseIdempotent(t *testing.T) {
	t.Run("closes source once", func(t *testing.T) {
		src := newTrackingIter()
		s := &aggregate{source: src}

		require.NoError(t, s.Close())
		require.NoError(t, s.Close())
		require.Equal(t, 1, src.closed)
	})

	t.Run("propagates source close error", func(t *testing.T) {
		srcErr := errors.New("source boom")
		src := newTrackingIter(srcErr)
		s := &aggregate{source: src}

		require.ErrorIs(t, s.Close(), srcErr)
	})

	t.Run("nil combiner", func(t *testing.T) {
		var s *aggregate
		require.NoError(t, s.Close())
	})
}

// // // // // // // // // // // // // // // // // // // // // // // // //
// Pipeline resource tree rollback

func TestRun_JoinRightBranchFailureRollsBackLeft(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	left := newTrackingIter()

	j := linkedJoin(
		testDatasource("l1", left, nil),
		// a failed datasource initialization produces no iterator
		testDatasource("l2", nil, errors.New("right init boom")),
		JoinPredicate{Left: "id", Right: "id"},
	)

	it, err := svc.run(ctx, j, false)
	require.Error(t, err)
	require.Nil(t, it)
	require.Contains(t, err.Error(), "right init boom")

	// the already opened left branch must be released when the right one fails
	require.Equal(t, 1, left.closed)
}

func TestRun_LinkRightBranchFailureRollsBackLeft(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	left := newTrackingIter()

	l := linkedLink(
		testDatasource("l1", left, nil),
		// a failed datasource initialization produces no iterator
		testDatasource("l2", nil, errors.New("right init boom")),
		LinkPredicate{Left: "id", Right: "id"},
	)

	it, err := svc.run(ctx, l, false)
	require.Error(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, left.closed)
}

func TestRun_JoinCombinerFailureReleasesBothBranches(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	left := newTrackingIter()
	right := newTrackingIter()

	j := linkedJoin(
		testDatasource("l1", left, nil),
		testDatasource("l2", right, nil),
		// unknown predicate attribute -> combiner init fails after both
		// branches were successfully opened
		JoinPredicate{Left: "nope", Right: "id"},
	)

	it, err := svc.run(ctx, j, false)
	require.Error(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, left.closed)
	require.Equal(t, 1, right.closed)
}

func TestRun_AggregateWrapperFailureRollsBackSource(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	src := newTrackingIter()
	ds := testDatasource("l1", src, nil)

	ag := &Aggregate{
		Ident:     "ag",
		RelSource: "l1",
		rel:       ds,

		// unknown attribute -> wrapper init/validation fails
		Group: []AggregateAttr{{
			Identifier: "g1",
			RawExpr:    "nope",
		}},
		OutAttributes: []AggregateAttr{{
			Identifier: "c1",
			RawExpr:    "count(id)",
			Type:       &TypeNumber{},
		}},
	}

	it, err := svc.run(ctx, ag, false)
	require.Error(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, src.closed)
}

func TestRun_DatasourceInitErrorClosesReturnedIterator(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	// defensive: a connection returns both, an iterator and an error
	open := newTrackingIter()
	ds := testDatasource("l1", open, errors.New("search boom"))

	it, err := svc.run(ctx, ds, false)
	require.Error(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, open.closed)
	require.Nil(t, ds.auxIter)
}

// // // // // // // // // // // // // // // // // // // // // // // // //
// Dryrun never leaves an active iterator

func TestRun_DryrunReleasesDatasourceIterator(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	open := newTrackingIter()
	ds := testDatasource("l1", open, nil)

	it, err := svc.run(ctx, ds, true)
	require.NoError(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, open.closed)
	require.Nil(t, ds.auxIter)
}

func TestRun_DryrunReleasesJoinTree(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	left := newTrackingIter()
	right := newTrackingIter()

	j := linkedJoin(
		testDatasource("l1", left, nil),
		testDatasource("l2", right, nil),
		JoinPredicate{Left: "id", Right: "id"},
	)
	// provide valid out attributes so the dryrun validation passes
	j.OutAttributes = []AttributeMapping{
		SimpleAttr{Ident: "l1.id", Src: "id", Props: MapProperties{IsPrimary: true, Type: TypeID{}}},
		SimpleAttr{Ident: "l2.id", Src: "id", Props: MapProperties{IsPrimary: true, Type: TypeID{}}},
	}
	j.LeftAttributes = saToMapping(simpleAttribute{ident: "id", primary: true, t: TypeID{}})
	j.RightAttributes = saToMapping(simpleAttribute{ident: "id", primary: true, t: TypeID{}})

	it, err := svc.run(ctx, j, true)
	require.NoError(t, err)
	require.Nil(t, it)
	require.Equal(t, 1, left.closed)
	require.Equal(t, 1, right.closed)
}

// // // // // // // // // // // // // // // // // // // // // // // // //
// Multiple runs over shared step definitions never share or double-close

func TestRun_MultipleRunsDoNotShareResources(t *testing.T) {
	ctx := context.Background()
	svc := testSvc(t)

	first := newTrackingIter()
	second := newTrackingIter()
	calls := 0

	ds := &Datasource{
		Ident: "l1",
		OutAttributes: saToMapping(simpleAttribute{
			ident:   "id",
			primary: true,
			t:       TypeID{},
		}),
	}
	conn := fakeTestConn{
		search: func(_ *Model) (Iterator, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			return second, nil
		},
	}
	ds.model = &Model{Ident: "l1"}
	ds.connection = MakeConnection(1, conn, ConnectionParams{}, ConnectionConfig{})

	// First run takes ownership of the first iterator
	one, err := svc.run(ctx, ds, false)
	require.NoError(t, err)
	require.Same(t, first, one)
	require.Nil(t, ds.auxIter)

	// Second run over the same step definition opens a fresh iterator
	two, err := svc.run(ctx, ds, false)
	require.NoError(t, err)
	require.Same(t, second, two)

	// The two runs must not share or double-close each other's resources
	require.NoError(t, one.Close())
	require.Equal(t, 1, first.closed)
	require.Equal(t, 0, second.closed)

	require.NoError(t, two.Close())
	require.Equal(t, 1, first.closed)
	require.Equal(t, 1, second.closed)

	// Exec without re-init can not reuse the closed iterator
	_, err = ds.exec(ctx)
	require.Error(t, err)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
