package dal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cortezaproject/corteza/server/pkg/filter"
)

type (
	// iteratorCloseErrors aggregates errors produced while closing the resources
	// of a pipeline run.
	//
	// Tearing down the resource tree must never stop at the first error --
	// doing so leaves sibling iterators (and the database connections behind
	// them) open. The errors are preserved in close order so the output stays
	// stable and the failing resource is easy to diagnose.
	iteratorCloseErrors struct {
		scope string
		errs  []error
	}
)

type (
	// Iterator provides an interface for loading data from the underlying store
	Iterator interface {
		Next(ctx context.Context) bool
		More(uint, ValueGetter) error
		Err() error
		Scan(ValueSetter) error
		Close() error

		BackCursor(ValueGetter) (*filter.PagingCursor, error)
		ForwardCursor(ValueGetter) (*filter.PagingCursor, error)

		// // -1 means unknown
		// Total() int
		// Cursor() any
		// // ... do we need anything else here?
	}

	iterator interface {
		Preload(context.Context, uint, *filter.PagingCursor) error
		Sorting() filter.SortExprSet
	}
)

// IteratorEncodeJSON helper function that encodes each item from the iterator as JSON
// and writes it to th given io.Writer.
//
// target initialization function is intentionally used to avoid use of reflection
func IteratorEncodeJSON(ctx context.Context, w io.Writer, iter Iterator, initTarget func() ValueSetter) (err error) {
	var (
		target   ValueSetter
		firstOut = false
	)

	for iter.Next(ctx) {
		if err = iter.Err(); err != nil {
			return
		}

		if firstOut {
			if _, err = w.Write([]byte(`,`)); err != nil {
				return
			}
		}

		firstOut = true

		target = initTarget()

		if err = iter.Scan(target); err != nil {
			return
		}

		err = json.NewEncoder(w).Encode(target)
		if err != nil {
			return
		}
	}

	return
}

// PreLoadCursor into iterator and check it exist then return the cursor
// @todo this should be move to the Iterator
func PreLoadCursor(ctx context.Context, iter Iterator, limit uint, reverse bool, r ValueGetter, fx func(Iterator) (bool, error)) (out *filter.PagingCursor, err error) {
	makeCursor := func() (*filter.PagingCursor, error) {
		if reverse {
			return iter.BackCursor(r)
		} else {
			return iter.ForwardCursor(r)
		}
	}

	out, err = makeCursor()
	if err != nil {
		return
	}

	err = iter.(iterator).Preload(ctx, limit, out)
	if err != nil {
		return nil, nil
	}

	for {
		if !iter.Next(ctx) {
			out = nil
			return
		}

		ok, err := fx(iter)
		if err != nil {
			return nil, err
		}

		if ok {
			return out, err

			// // @todo Skip the things we don't have access to; could cause some edge cases so probably not
			// // It adds some performance since we skip unneeded stuff but could some records change in the mean time?
			// // return makeCursor()
		}
	}
}

// IteratorSorting return iterator sorting
// @todo this should be move to the Iterator
func IteratorSorting(iter Iterator) filter.SortExprSet {
	return iter.(iterator).Sorting()
}

func (e *iteratorCloseErrors) Error() string {
	var s strings.Builder
	s.WriteString(e.scope)
	if len(e.errs) > 1 {
		fmt.Fprintf(&s, " (%d errors)", len(e.errs))
	}
	s.WriteString(":")
	for i, err := range e.errs {
		fmt.Fprintf(&s, " %d. %s;", i+1, err.Error())
	}
	return s.String()
}

// Unwrap makes every individual close error discoverable via errors.Is/errors.As
func (e *iteratorCloseErrors) Unwrap() []error {
	return e.errs
}

// closeIterators closes every provided iterator in order, continuing after a
// failure so that one misbehaving child can never keep the remaining resources
// of the pipeline run (and their database connections) open.
//
// nil iterators are skipped. A single error is returned as-is; multiple errors
// are aggregated in close order.
func closeIterators(ii ...Iterator) error {
	var ee []error
	for _, i := range ii {
		if i == nil {
			continue
		}
		if err := i.Close(); err != nil {
			ee = append(ee, err)
		}
	}

	switch len(ee) {
	case 0:
		return nil
	case 1:
		return ee[0]
	default:
		return &iteratorCloseErrors{scope: "failed to close pipeline iterators", errs: ee}
	}
}
