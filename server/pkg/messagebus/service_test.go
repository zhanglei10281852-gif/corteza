package messagebus

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cortezaproject/corteza/server/pkg/eventbus"
	"github.com/cortezaproject/corteza/server/pkg/messagebus/types"
	"github.com/cortezaproject/corteza/server/pkg/options"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type (
	mockQueueServicer struct {
		mu sync.Mutex

		list      []types.QueueDb
		searchErr error
		// afterSearch, when set, is invoked after the queue list snapshot
		// was captured (used to orchestrate reload ordering in tests)
		afterSearch func()

		messages []types.QueueMessage
	}

	mockConsumer struct {
		write func(ctx context.Context, p []byte) error
	}
)

var (
	logger   = zap.NewNop()
	mOptions = &options.MessagebusOpt{Enabled: true, LogEnabled: true}
)

// /////////////////////////////////////////////////////////////////////////////
// Servicer mock
// /////////////////////////////////////////////////////////////////////////////

func (s *mockQueueServicer) SearchQueues(_ context.Context, f types.QueueFilter) ([]types.QueueDb, types.QueueFilter, error) {
	s.mu.Lock()

	var (
		out []types.QueueDb
		err = s.searchErr
	)

	if s.searchErr == nil {
		out = append([]types.QueueDb(nil), s.list...)
	}

	hook := s.afterSearch
	s.mu.Unlock()

	if hook != nil {
		hook()
	}

	return out, f, err
}

func (s *mockQueueServicer) CreateQueueMessage(_ context.Context, m types.QueueMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, m)
	return nil
}

func (s *mockQueueServicer) ProcessQueueMessage(_ context.Context, _ uint64, m types.QueueMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, m)
	return nil
}

func (s *mockQueueServicer) CreateQueueEvent(q string, p []byte) eventbus.Event { return nil }

func (s *mockQueueServicer) persisted() []types.QueueMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]types.QueueMessage(nil), s.messages...)
}

func (s *mockQueueServicer) setList(qq ...types.QueueDb) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.list = qq
}

// /////////////////////////////////////////////////////////////////////////////
// Consumer mock
// /////////////////////////////////////////////////////////////////////////////

func (c *mockConsumer) Write(ctx context.Context, p []byte) error {
	return c.write(ctx, p)
}

// /////////////////////////////////////////////////////////////////////////////
// Helpers
// /////////////////////////////////////////////////////////////////////////////

func queueDb(name, consumer string) types.QueueDb {
	return types.QueueDb{Queue: name, Consumer: consumer}
}

func queueSetWith(name string, c types.Consumer) types.QueueSet {
	return types.QueueSet{
		name: {Name: name, Consumer: c},
	}
}

// activateTestGeneration builds, starts and publishes a generation directly
// (bypassing store-backed ReloadQueues), returning the new generation
func (mb *messageBus) activateTestGeneration(qq types.QueueSet) *generation {
	mb.activeLock.Lock()
	mb.seq++
	g := newGeneration(mb.seq, fmt.Sprintf("test-%d", mb.seq), qq)
	mb.activeLock.Unlock()

	mb.generations.Add(1)
	g.run(mb.ctx, mb.logger)

	mb.activeLock.Lock()
	previous := mb.active
	mb.active = g
	mb.activeLock.Unlock()

	if previous != nil {
		previous.shutdown()
		mb.generations.Done()
	}

	return g
}

func waitUntil(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}

		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}

	require.True(t, fn(), "condition not met within %s", timeout)
}

// /////////////////////////////////////////////////////////////////////////////
// Tests
// /////////////////////////////////////////////////////////////////////////////

func TestNewIsEmpty(t *testing.T) {
	req := require.New(t)
	mb := New(mOptions, logger)

	req.Nil(mb.activeGeneration())

	// Close is idempotent
	req.NotPanics(func() {
		mb.Close()
		mb.Close()
	})
}

func TestConsume(t *testing.T) {
	req := require.New(t)

	mb := New(mOptions, logger)
	defer mb.Close()

	var (
		mu     sync.Mutex
		got    [][]byte
		wg     sync.WaitGroup
		expect = [][]byte{
			[]byte("mock payload"),
			[]byte("second mock payload"),
		}
	)

	wg.Add(2)

	mb.activateTestGeneration(queueSetWith("foobar", &mockConsumer{
		write: func(_ context.Context, p []byte) error {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
			wg.Done()
			return nil
		},
	}))

	mb.Push("foobar", expect[0])
	mb.Push("foobar", expect[1])
	wg.Wait()

	req.Equal(expect, got)
}

func TestPushUnknownQueueRejected(t *testing.T) {
	req := require.New(t)

	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = &mockQueueServicer{}

	mb.activateTestGeneration(queueSetWith("known", &mockConsumer{
		write: func(context.Context, []byte) error { return nil },
	}))

	err := mb.push("missing", []byte("x"))
	req.ErrorIs(err, ErrQueueNotActive)
}

func TestPushBeforeInitRejected(t *testing.T) {
	req := require.New(t)

	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = &mockQueueServicer{}

	req.ErrorIs(mb.push("q", []byte("x")), ErrNotInitialized)
}

func TestDisabledPushIsNoopAndReloadSkipped(t *testing.T) {
	req := require.New(t)

	mb := New(&options.MessagebusOpt{Enabled: false}, logger)
	defer mb.Close()

	// no active generation, no servicer — Push must still be a silent noop
	req.NotPanics(func() { mb.Push("q", []byte("x")) })
	req.NoError(mb.ReloadQueues(context.Background()))
	req.Nil(mb.activeGeneration())
}

func TestReloadActivatesGeneration(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))

	gen := mb.activeGeneration()
	req.NotNil(gen)
	req.Equal(uint64(1), gen.seq)
	req.Contains(gen.queues, "q1")

	mb.Push("q1", []byte("hello"))
	waitUntil(t, time.Second, func() bool { return len(svc.persisted()) == 1 })

	req.Equal([]byte("hello"), svc.persisted()[0].Payload)
}

func TestReloadUnchangedKeepsGeneration(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))
	first := mb.activeGeneration()

	req.NoError(mb.ReloadQueues(ctx))
	second := mb.activeGeneration()

	req.Same(first, second)
	select {
	case <-first.done:
		req.Fail("unchanged generation should not be retired")
	default:
	}
}

func TestReloadSearchFailureKeepsPreviousGeneration(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))
	previous := mb.activeGeneration()

	// query fails — reload must report it and keep previous generation
	svc.searchErr = errors.New("boom")
	err := mb.ReloadQueues(ctx)
	req.Error(err)

	var reloadErr *ReloadError
	req.True(errors.As(err, &reloadErr))
	req.Equal("queue search", reloadErr.Stage)
	req.Same(previous, mb.activeGeneration())

	// previous generation keeps serving traffic
	svc.searchErr = nil
	mb.Push("q1", []byte("still-here"))
	waitUntil(t, time.Second, func() bool { return len(svc.persisted()) == 1 })
}

func TestReloadConsumerFailureKeepsPreviousGeneration(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))
	previous := mb.activeGeneration()

	// new set references a consumer that can not be initialized —
	// the whole new generation must be discarded
	svc.setList(
		queueDb("q1", string(types.ConsumerStore)),
		queueDb("q2", "redis"),
	)

	err := mb.ReloadQueues(ctx)
	req.Error(err)

	var reloadErr *ReloadError
	req.True(errors.As(err, &reloadErr))
	req.Equal("consumer initialization", reloadErr.Stage)
	req.Equal("q2", reloadErr.Queue)

	// old generation untouched, q2 never visible
	req.Same(previous, mb.activeGeneration())
	req.NotContains(mb.activeGeneration().queues, "q2")

	// retrying with a valid set applies it
	svc.setList(queueDb("q1", string(types.ConsumerStore)), queueDb("q2", string(types.ConsumerEventbus)))
	req.NoError(mb.ReloadQueues(ctx))
	req.Contains(mb.activeGeneration().queues, "q2")
}

// TestGenerationHandoffBinding proves that a message already accepted by the
// old generation is delivered to the old consumer while new messages after
// the switch go to the new consumer — exactly once each.
func TestGenerationHandoffBinding(t *testing.T) {
	req := require.New(t)

	mb := New(mOptions, logger)
	defer mb.Close()

	var (
		mu     sync.Mutex
		oldGot [][]byte
		newGot [][]byte

		accepted = make(chan struct{})
		release  = make(chan struct{})
		handoff  = make(chan struct{})
	)

	// old generation blocks processing the first message until we release it
	old := mb.activateTestGeneration(queueSetWith("q", &mockConsumer{
		write: func(_ context.Context, p []byte) error {
			close(accepted)
			<-release
			mu.Lock()
			oldGot = append(oldGot, append([]byte(nil), p...))
			mu.Unlock()
			return nil
		},
	}))

	go mb.Push("q", []byte("old-message"))
	<-accepted

	// switch while the old message is still in flight; handoff can only
	// complete after we let the old consumer finish
	go func() {
		mb.activateTestGeneration(queueSetWith("q", &mockConsumer{
			write: func(_ context.Context, p []byte) error {
				mu.Lock()
				newGot = append(newGot, append([]byte(nil), p...))
				mu.Unlock()
				return nil
			},
		}))
		close(handoff)
	}()

	// give the handoff a moment to park on old-generation drain
	waitUntil(t, time.Second, func() bool {
		select {
		case <-handoff:
			return false // handoff must not finish while old message is in flight
		default:
			return true
		}
	})

	close(release)
	<-handoff

	// old generation retired, its accepted message delivered exactly once
	select {
	case <-old.done:
	case <-time.After(time.Second):
		req.Fail("old generation not retired")
	}

	// message pushed after switch belongs to the new generation
	mb.Push("q", []byte("new-message"))
	waitUntil(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(newGot) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	req.Equal([][]byte{[]byte("new-message")}, newGot)
	req.Equal([][]byte{[]byte("old-message")}, oldGot)
}

func TestDeletedQueueRejectsNewWrites(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))

	mb.Push("q1", []byte("before-delete"))
	waitUntil(t, time.Second, func() bool { return len(svc.persisted()) == 1 })

	// queue removed from persisted set
	svc.setList()
	req.NoError(mb.ReloadQueues(ctx))

	err := mb.push("q1", []byte("after-delete"))
	req.ErrorIs(err, ErrQueueNotActive)
	req.Len(svc.persisted(), 1)
}

// TestReloadSerializationOrder makes sure an older slow reload can never
// overwrite a newer configuration: the slow reload captures an older
// persisted snapshot, but once it completes the queued newer reload must
// advance the runtime to the newest configuration.
func TestReloadSerializationOrder(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	var (
		firstSearchDone = make(chan struct{})
		allowFirstBuild = make(chan struct{})
		once            sync.Once
	)

	svc.afterSearch = func() {
		once.Do(func() {
			close(firstSearchDone)
			<-allowFirstBuild
		})
	}

	// old configuration when the first reload starts
	svc.setList(queueDb("q1", string(types.ConsumerStore)))

	// slow first reload: captured v1, paused before building it
	firstDone := make(chan error, 1)
	go func() { firstDone <- mb.ReloadQueues(ctx) }()

	<-firstSearchDone

	// second reload is queued while the first is paused;
	// the persisted configuration moves forward meanwhile
	secondDone := make(chan error, 1)
	go func() { secondDone <- mb.ReloadQueues(ctx) }()

	svc.setList(
		queueDb("q1", string(types.ConsumerStore)),
		queueDb("q2", string(types.ConsumerStore)),
	)
	close(allowFirstBuild)

	req.NoError(<-firstDone)
	req.NoError(<-secondDone)

	active := mb.activeGeneration()
	req.Contains(active.queues, "q2")
	req.Equal(uint64(2), active.seq)
}

// TestPushExactlyOnceAcrossRapidHandoffs hammers Push with many messages
// while generations are switched continuously; every payload must be
// delivered exactly once.
func TestPushExactlyOnceAcrossRapidHandoffs(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{}
	mb := New(mOptions, logger)
	defer mb.Close()
	mb.qservicer = svc

	mkList := func(dispatch bool) []types.QueueDb {
		return []types.QueueDb{{
			Queue:    "q1",
			Consumer: string(types.ConsumerStore),
			Meta:     types.QueueMeta{DispatchEvents: dispatch},
		}}
	}

	svc.setList(mkList(false)...)
	req.NoError(mb.ReloadQueues(ctx))

	const (
		pushers   = 16
		perPusher = 50
	)

	var (
		pushWg     sync.WaitGroup
		stopReload = make(chan struct{})
		reloadWG   sync.WaitGroup
		toggle     int32
	)

	reloadWG.Add(1)
	go func() {
		defer reloadWG.Done()
		for {
			select {
			case <-stopReload:
				return
			default:
				svc.setList(mkList(atomic.AddInt32(&toggle, 1)%2 == 0)...)
				_ = mb.ReloadQueues(ctx)
			}
		}
	}()

	pushWg.Add(pushers)
	for i := 0; i < pushers; i++ {
		go func(p int) {
			defer pushWg.Done()
			for j := 0; j < perPusher; j++ {
				mb.Push("q1", []byte(fmt.Sprintf("%d-%d", p, j)))
			}
		}(i)
	}
	pushWg.Wait()

	close(stopReload)
	reloadWG.Wait()

	// final reload to settle and Close to drain everything in flight
	svc.setList(mkList(true)...)
	req.NoError(mb.ReloadQueues(ctx))
	mb.Close()

	counts := make(map[string]int)
	for _, m := range svc.persisted() {
		counts[string(m.Payload)]++
	}

	req.Len(counts, pushers*perPusher)
	for payload, n := range counts {
		req.Equalf(1, n, "payload %q delivered %d times", payload, n)
	}
}

func TestCloseDrainsAndRejectsNewPushes(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	svc := &mockQueueServicer{list: []types.QueueDb{queueDb("q1", string(types.ConsumerStore))}}
	mb := New(mOptions, logger)
	mb.qservicer = svc

	req.NoError(mb.ReloadQueues(ctx))
	gen := mb.activeGeneration()

	mb.Close()

	// all dispatcher goroutines are gone
	select {
	case <-gen.done:
	case <-time.After(time.Second):
		req.Fail("dispatcher goroutine leaked after Close")
	}

	// pushes after close are rejected
	req.ErrorIs(mb.push("q1", []byte("late")), ErrClosed)

	// Close is idempotent
	req.NotPanics(func() { mb.Close() })
}

func TestCloseCancelsInFlightConsumer(t *testing.T) {
	req := require.New(t)

	mb := New(mOptions, logger)

	var (
		started   = make(chan struct{})
		finished  = make(chan struct{})
		completed int32
	)

	mb.activateTestGeneration(queueSetWith("q", &mockConsumer{
		write: func(ctx context.Context, _ []byte) error {
			close(started)
			<-ctx.Done()
			if atomic.AddInt32(&completed, 1) == 1 {
				close(finished)
			}
			return ctx.Err()
		},
	}))

	go mb.Push("q", []byte("in-flight"))
	<-started

	done := make(chan struct{})
	go func() { mb.Close(); close(done) }()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		req.Fail("in-flight message not canceled on Close")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		req.Fail("Close did not return after canceling in-flight handoff")
	}
}
