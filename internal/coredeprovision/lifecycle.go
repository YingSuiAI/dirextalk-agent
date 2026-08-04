package coredeprovision

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned to new business mutations after account deprovision
// has started. A completed/failed external purge keeps the account closed so
// a retry can finish cleanup without allowing a new mutation to recreate data.
var ErrClosed = errors.New("account lifecycle is closed")

// LifecycleFence is the process-local account lifecycle boundary. Readers are
// admitted for ordinary mutations; BeginPurge transitions the fence to a
// draining writer, waits for every admitted reader, and rejects all new
// readers until the account is permanently sealed. A retry of deprovision is
// still allowed to acquire the writer while sealed so external cleanup can be
// resumed after a transient failure.
type LifecycleFence struct {
	mu        sync.Mutex
	changed   chan struct{}
	readers   int
	writer    bool
	sealed    bool
	sealHooks []func()
}

func NewLifecycleFence() *LifecycleFence {
	return &LifecycleFence{changed: make(chan struct{})}
}

func (f *LifecycleFence) ensure() error {
	if f == nil {
		return ErrInvalid
	}
	return nil
}

// Enter admits one database/filesystem/external mutation. The returned
// release function must be called exactly once by the caller.
func (f *LifecycleFence) Enter(ctx context.Context) (func(), error) {
	if err := f.ensure(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		f.mu.Lock()
		if f.sealed {
			f.mu.Unlock()
			return nil, ErrClosed
		}
		if f.writer {
			wait := f.changed
			f.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
				continue
			}
		}
		f.readers++
		f.mu.Unlock()
		return sync.OnceFunc(func() { f.releaseReader() }), nil
	}
}

func (f *LifecycleFence) releaseReader() {
	f.mu.Lock()
	if f.readers > 0 {
		f.readers--
	}
	f.signalLocked()
	f.mu.Unlock()
}

// PurgeLease owns the exclusive lifecycle writer. Finish permanently seals
// the account; Abort is only valid before the durable database phase succeeds.
type PurgeLease struct {
	fence *LifecycleFence
	once  sync.Once
}

func (f *LifecycleFence) BeginPurge(ctx context.Context) (*PurgeLease, error) {
	if err := f.ensure(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		f.mu.Lock()
		if !f.writer {
			f.writer = true
			f.signalLocked()
			for f.readers != 0 {
				wait := f.changed
				f.mu.Unlock()
				select {
				case <-ctx.Done():
					f.mu.Lock()
					f.writer = false
					f.signalLocked()
					f.mu.Unlock()
					return nil, ctx.Err()
				case <-wait:
					f.mu.Lock()
				}
			}
			f.mu.Unlock()
			return &PurgeLease{fence: f}, nil
		}
		wait := f.changed
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait:
		}
	}
}

func (l *PurgeLease) Finish() {
	if l == nil || l.fence == nil {
		return
	}
	l.once.Do(func() {
		f := l.fence
		f.mu.Lock()
		f.sealed = true
		f.writer = false
		hooks := append([]func(){}, f.sealHooks...)
		f.sealHooks = nil
		f.signalLocked()
		f.mu.Unlock()
		for _, hook := range hooks {
			if hook != nil {
				hook()
			}
		}
	})
}

func (l *PurgeLease) Abort() {
	if l == nil || l.fence == nil {
		return
	}
	l.once.Do(func() {
		f := l.fence
		f.mu.Lock()
		f.writer = false
		f.signalLocked()
		f.mu.Unlock()
	})
}

func (f *LifecycleFence) signalLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

// RestoreSealed rehydrates the process-local fence from the durable
// deprovision ledger during startup. It is intentionally one-way: a process
// restart must never reopen an account whose purge had already been claimed.
func (f *LifecycleFence) RestoreSealed() error {
	if err := f.ensure(); err != nil {
		return err
	}
	f.mu.Lock()
	f.sealed = true
	hooks := append([]func(){}, f.sealHooks...)
	f.sealHooks = nil
	f.signalLocked()
	f.mu.Unlock()
	for _, hook := range hooks {
		if hook != nil {
			hook()
		}
	}
	return nil
}

// OnSealed registers a callback that runs once the account becomes
// permanently sealed. Hooks are invoked outside the fence mutex so they may
// close dependent resources (for example operation watchers) without
// deadlocking lifecycle admission. A hook registered after startup restore is
// invoked immediately.
func (f *LifecycleFence) OnSealed(hook func()) {
	if f == nil || hook == nil {
		return
	}
	f.mu.Lock()
	if f.sealed {
		f.mu.Unlock()
		hook()
		return
	}
	f.sealHooks = append(f.sealHooks, hook)
	f.mu.Unlock()
}

func (f *LifecycleFence) IsSealed() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	sealed := f.sealed
	f.mu.Unlock()
	return sealed
}
