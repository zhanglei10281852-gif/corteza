package messagebus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cortezaproject/corteza/server/pkg/messagebus/consumer"
	"github.com/cortezaproject/corteza/server/pkg/messagebus/store"
	"github.com/cortezaproject/corteza/server/pkg/messagebus/types"
	"github.com/cortezaproject/corteza/server/pkg/options"
	"go.uber.org/zap"
)

var (
	// global service
	gMbus *messageBus
)

var (
	// ErrClosed is returned when the messagebus is (being) closed
	ErrClosed = errors.New("messagebus is closed")

	// ErrNotInitialized is returned before the first successful queue load
	ErrNotInitialized = errors.New("messagebus is not initialized")

	// ErrQueueNotActive is returned when the queue a message is pushed to
	// is not visible on the active generation (unknown, disabled or deleted)
	ErrQueueNotActive = errors.New("message queue is not active")
)

// ReloadError explains why a persisted queue configuration could not be
// applied to the running messagebus.
//
// When ReloadError is returned the previous generation keeps serving all
// traffic. The change is already persisted, so re-triggering a reload
// (e.g. by saving the queue again) applies it without any data change.
type ReloadError struct {
	// Stage at which the reload failed (search or consumer initialization)
	Stage string

	// Queue is the name of the queue when the failure happened while
	// initializing its consumer
	Queue string

	// Err holds the underlying cause
	Err error
}

func (e *ReloadError) Error() string {
	if e.Queue != "" {
		return fmt.Sprintf("could not apply queue configuration: %s for queue %q failed: %v", e.Stage, e.Queue, e.Err)
	}

	return fmt.Sprintf("could not apply queue configuration: %s failed: %v", e.Stage, e.Err)
}

func (e *ReloadError) Unwrap() error { return e.Err }

type (
	// generation is one immutable, fully initialized snapshot of the queue
	// configuration. Messages accepted by a generation are always delivered
	// to that generation's consumers, even when a newer generation takes over.
	generation struct {
		// Monotonic generation sequence number
		seq uint64

		// Fingerprint of the persisted queue set this generation was built from
		fingerprint string

		// Immutable queue index; never mutated after publication
		queues types.QueueSet

		// Unbuffered input channel.
		//
		// A message is considered accepted by this generation only when
		// the dispatcher goroutine receives it from in.
		in chan types.Message

		// retire signals the dispatcher to stop accepting new messages
		retire chan struct{}

		// done is closed when the dispatcher goroutine has exited
		done chan struct{}

		// inFlight counts messages that were either accepted by the
		// dispatcher or whose rendezvous is in progress.
		inFlight sync.WaitGroup

		// reserveLock makes sure no reservation slips in after shutdown
		// started draining inFlight.
		reserveLock sync.Mutex

		retireOnce sync.Once
	}

	messageBus struct {
		opts      *options.MessagebusOpt
		qservicer types.QueueServicer
		logger    *zap.Logger

		// reloadLock serializes complete reload cycles (load, build,
		// activation and retirement) so overlapping reloads can never
		// interleave and older reloads can never win over newer ones.
		reloadLock sync.Mutex

		// activeLock guards the active generation pointer and the sequence
		activeLock sync.RWMutex
		active     *generation
		seq        uint64

		// generations tracks every generation that was ever activated
		// so Close can wait until all of them are fully retired
		generations sync.WaitGroup

		// Long-lived context for generation dispatchers; never derived
		// from a request context so it outlives the management request
		// that triggered a reload
		ctx       context.Context
		cancelCtx context.CancelFunc

		// closed is closed when the messagebus starts shutting down
		closed    chan struct{}
		closeOnce sync.Once
	}
)

func Service() *messageBus {
	return gMbus
}

func Set(m *messageBus) {
	gMbus = m
}

// Setup handles the singleton service
func Setup(opts *options.MessagebusOpt, log *zap.Logger) {
	if gMbus != nil {
		return
	}

	gMbus = New(opts, log)
}

func New(opts *options.MessagebusOpt, logger *zap.Logger) *messageBus {
	ctx, cancel := context.WithCancel(context.Background())

	return &messageBus{
		opts:   opts,
		logger: logger,

		ctx:       ctx,
		cancelCtx: cancel,
		closed:    make(chan struct{}),
	}
}

// Init takes care of preloading the queue and creating
// a connection to the store of their choice.
//
// It loads and activates the first queue generation. When loading fails,
// no generation is activated and the error is returned; Push keeps rejecting
// messages until a successful ReloadQueues.
func (mb *messageBus) Init(ctx context.Context, storer types.QueueServicer) error {
	// set store now, on New() we do not have store yet
	mb.qservicer = storer

	return mb.ReloadQueues(ctx)
}

// ReloadQueues loads the persisted queue set and hands traffic over to a new
// generation.
//
// The handoff is synchronous and serialized:
//   - the entire persisted set is loaded and every consumer is initialized
//     before the new generation is published;
//   - on query or consumer initialization failure nothing is swapped and the
//     previous generation keeps serving all traffic (a ReloadError describing
//     the failure is returned);
//   - when the persisted set did not change the active generation is left
//     untouched;
//   - after the atomic switch the previous generation finishes every message
//     it accepted before it is retired.
func (mb *messageBus) ReloadQueues(ctx context.Context) error {
	// preserve existing behavior when the messagebus is disabled
	if !mb.opts.Enabled {
		return nil
	}

	mb.reloadLock.Lock()
	defer mb.reloadLock.Unlock()

	select {
	case <-mb.closed:
		return ErrClosed
	default:
	}

	if mb.qservicer == nil {
		return ErrNotInitialized
	}

	mb.logger.Debug("reloading queues")

	// 1. load the complete persisted queue set
	list, _, err := mb.qservicer.SearchQueues(ctx, types.QueueFilter{})
	if err != nil {
		return &ReloadError{Stage: "queue search", Err: err}
	}

	// 2. build the candidate generation offline;
	//    a single failure aborts the whole reload and nothing is swapped
	candidate := make(types.QueueSet, len(list))

	for _, q := range list {
		mb.logger.Debug("initializing queue", zap.String("queue", q.Queue))

		c, err := mb.initConsumer(ctx, q.Queue, q.Consumer)
		if err != nil {
			mb.logger.Warn("could not init consumer for queue", zap.String("queue", q.Queue), zap.Error(err))
			return &ReloadError{Stage: "consumer initialization", Queue: q.Queue, Err: err}
		}

		if s, is := c.(store.Storer); is {
			s.SetStore(mb.qservicer)
		}

		candidate[q.Queue] = &types.Queue{
			Consumer: c,
			Name:     q.Queue,
			Meta:     types.QueueMeta(q.Meta),
		}
	}

	// 3. unchanged configuration must not disturb the running generation
	fp := fingerprintQueues(list)
	if current := mb.activeGeneration(); current != nil && current.fingerprint == fp {
		mb.logger.Debug("queue configuration unchanged, keeping active generation")
		return nil
	}

	// 4. allocate and start the new generation BEFORE publishing it
	mb.activeLock.Lock()
	mb.seq++
	gen := newGeneration(mb.seq, fp, candidate)
	mb.activeLock.Unlock()

	mb.generations.Add(1)
	gen.run(mb.ctx, mb.logger)

	// 5. atomic publication; runtime only moves forward by generation number
	mb.activeLock.Lock()
	if mb.active != nil && gen.seq <= mb.active.seq {
		mb.activeLock.Unlock()

		// Defense in depth: with reloadLock this can not happen.
		gen.shutdown()
		mb.generations.Done()
		return &ReloadError{Stage: "generation activation", Err: errors.New("stale generation")}
	}

	previous := mb.active
	mb.active = gen
	mb.activeLock.Unlock()

	// 6. retire previous generation and let it finish all accepted messages
	if previous != nil {
		previous.shutdown()
		mb.generations.Done()
	}

	mb.logger.Debug("queues reloaded",
		zap.Uint64("generation", gen.seq),
		zap.Int("queues", len(candidate)))

	return nil
}

// Close stops accepting new messages, cancels in-flight processing and waits
// for every generation (and its dispatcher goroutine) to retire.
func (mb *messageBus) Close() {
	mb.closeOnce.Do(func() {
		close(mb.closed)
	})

	// wait for any in-flight reload to finish the handoff before tearing down
	mb.reloadLock.Lock()
	defer mb.reloadLock.Unlock()

	mb.cancelCtx()

	mb.activeLock.Lock()
	current := mb.active
	mb.active = nil
	mb.activeLock.Unlock()

	if current != nil {
		current.shutdown()
		mb.generations.Done()
	}

	// wait for all generations handed over during reloads
	mb.generations.Wait()
}

// Push accepts a message for queue q with payload p.
//
// The message is bound to the generation visible at the time it is accepted:
// it rendezvous with exactly that generation's dispatcher and is delivered to
// that generation's consumer exactly once. If the generation retires before
// the rendezvous, Push retries against the newest generation. New writes to
// unknown/disabled/deleted queues are rejected.
//
// Existing behavior when the messagebus is disabled is preserved: the
// message is silently ignored (debug log only).
func (mb *messageBus) Push(q string, p []byte) {
	if !mb.opts.Enabled {
		mb.logger.Debug("message will not be sent, messagebus disabled", zap.String("queue", q))
		return
	}

	mb.logger.Debug("pushing message", zap.String("queue", q))

	if err := mb.push(q, p); err != nil {
		mb.logger.Warn("could not accept message", zap.String("queue", q), zap.Error(err))
	}
}

func (mb *messageBus) push(q string, p []byte) error {
	for {
		select {
		case <-mb.closed:
			return ErrClosed
		default:
		}

		gen := mb.activeGeneration()
		if gen == nil {
			return ErrNotInitialized
		}

		if _, ok := gen.queues[q]; !ok {
			// queue is not visible on the active generation — it is
			// unknown, disabled or was deleted; refuse new writes
			return fmt.Errorf("%w: %s", ErrQueueNotActive, q)
		}

		// reserve an in-flight slot before the rendezvous so retirement
		// waits for this message if the dispatcher accepts it
		if !gen.reserve() {
			// generation retired before we could reserve; retry
			// with the newest visible generation
			continue
		}

		select {
		case gen.in <- types.Message{P: p, Q: q}:
			// accepted by exactly this generation; the dispatcher is
			// now responsible for a single consumer delivery
			return nil

		case <-gen.retire:
			// not accepted by anyone; release the reservation and
			// re-bind the message to the newest generation
			gen.inFlight.Done()
			continue

		case <-mb.closed:
			gen.inFlight.Done()
			return ErrClosed
		}
	}
}

func (mb *messageBus) activeGeneration() *generation {
	mb.activeLock.RLock()
	defer mb.activeLock.RUnlock()

	return mb.active
}

// newGeneration constructs a generation with the given sequence,
// configuration fingerprint and immutable queue index
func newGeneration(seq uint64, fp string, qq types.QueueSet) *generation {
	return &generation{
		seq:         seq,
		fingerprint: fp,
		queues:      qq,
		in:          make(chan types.Message),
		retire:      make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// reserve claims an in-flight slot on the generation unless it was retired
func (g *generation) reserve() bool {
	g.reserveLock.Lock()
	defer g.reserveLock.Unlock()

	select {
	case <-g.retire:
		return false
	default:
	}

	g.inFlight.Add(1)

	return true
}

// run starts the generation's single dispatcher goroutine
func (g *generation) run(ctx context.Context, log *zap.Logger) {
	go func() {
		defer close(g.done)

		for {
			select {
			case m := <-g.in:
				g.dispatch(ctx, log, m)

			case <-g.retire:
				log.Debug("generation retired", zap.Uint64("generation", g.seq))
				return

			case <-ctx.Done():
				log.Debug("generation stopped", zap.Uint64("generation", g.seq))
				return
			}
		}
	}()
}

// dispatch delivers one accepted message to the consumer of this generation
// exactly once. It owns the in-flight reservation until it is done.
func (g *generation) dispatch(ctx context.Context, log *zap.Logger, m types.Message) {
	defer g.inFlight.Done()

	log = log.With(zap.String("queue", m.Q), zap.Uint64("generation", g.seq))

	q := g.queues[m.Q]
	if q == nil {
		log.Warn("could not get queue settings")
		return
	}

	if err := q.Consumer.Write(ctx, m.P); err != nil {
		log.Warn("could not add message to queue", zap.Error(err))
		return
	}

	log.Debug("wrote payload to queue")
}

// shutdown stops the dispatcher and blocks until every message the generation
// accepted was processed (or aborted through context cancellation on Close).
func (g *generation) shutdown() {
	g.retireOnce.Do(func() {
		close(g.retire)
	})

	<-g.done

	// under reserveLock so no reservation can be added after Wait
	g.reserveLock.Lock()
	g.inFlight.Wait()
	g.reserveLock.Unlock()
}

// initHandler returns a new instance for a specific handler
func (mb *messageBus) initConsumer(ctx context.Context, q string, c string) (cns types.Consumer, err error) {
	switch c {
	case string(types.ConsumerEventbus):
		cns = consumer.NewEventbusConsumer(q, mb.qservicer)
		return

	case string(types.ConsumerStore):
		cns = consumer.NewStoreConsumer(q, mb.qservicer)
		return

	default:
		err = fmt.Errorf("message queue consumer %s not implemented", c)
		return
	}
}

// fingerprintQueues produces a stable fingerprint of the persisted queue set
func fingerprintQueues(list []types.QueueDb) string {
	names := make([]string, 0, len(list))
	byName := make(map[string]types.QueueDb, len(list))

	for _, q := range list {
		names = append(names, q.Queue)
		byName[q.Queue] = q
	}

	sort.Strings(names)

	h := sha256.New()

	for _, name := range names {
		q := byName[name]

		meta, err := json.Marshal(types.QueueMeta(q.Meta))
		if err != nil {
			meta = []byte("{}")
		}

		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", q.Queue, q.Consumer, string(meta))
	}

	return hex.EncodeToString(h.Sum(nil))
}
