/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpstreamResolverCachesSuccessfulInitialization(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	var callbackCalls atomic.Int32
	var startedOnce sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
		initCalls.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		return testUpstream(raw), nil
	}

	resolver := testUpstreamResolver(t, func(*url.URL, *Upstream) error {
		callbackCalls.Add(1)
		return nil
	})
	const callers = 32
	results := make(chan *Upstream, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			upstream, err := resolver.GetUpstream()
			if err != nil {
				errs <- err
				return
			}
			results <- upstream
		})
	}

	<-started
	close(release)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("GetUpstream() error = %v", err)
	}
	if got := initCalls.Load(); got != 1 {
		t.Fatalf("initializer calls = %d, want 1", got)
	}
	if got := callbackCalls.Load(); got != 1 {
		t.Fatalf("callback calls = %d, want 1", got)
	}

	var first *Upstream
	for upstream := range results {
		if upstream == nil {
			t.Fatal("GetUpstream() returned nil upstream")
		}
		if first == nil {
			first = upstream
			continue
		}
		if upstream != first {
			t.Fatal("concurrent callers received different upstream pointers")
		}
	}
	if first == nil {
		t.Fatal("no successful result")
	}

	if upstream, err := resolver.GetUpstream(); err != nil || upstream != first {
		t.Fatalf("cached GetUpstream() = (%p, %v), want (%p, nil)", upstream, err, first)
	}
	if got := initCalls.Load(); got != 1 {
		t.Fatalf("initializer ran after success: %d calls", got)
	}
}

func TestUpstreamResolverRetriesInitializationFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
		if initCalls.Add(1) == 1 {
			return nil, errors.New("temporary resolution failure")
		}
		return testUpstream(raw), nil
	}

	resolver := testUpstreamResolver(t, func(*url.URL, *Upstream) error { return nil })
	if _, err := resolver.GetUpstream(); err == nil {
		t.Fatal("first GetUpstream() error = nil, want failure")
	}
	upstream, err := resolver.GetUpstream()
	if err != nil {
		t.Fatalf("second GetUpstream() error = %v", err)
	}
	if upstream == nil {
		t.Fatal("second GetUpstream() returned nil upstream")
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("initializer calls = %d, want 2", got)
	}
}

func TestUpstreamResolverRetriesCallbackFailure(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	var initCalls atomic.Int32
	var callbackCalls atomic.Int32
	newUpstreamFunc = func(_ context.Context, raw *url.URL, _ string) (*Upstream, error) {
		initCalls.Add(1)
		return testUpstream(raw), nil
	}

	resolver := testUpstreamResolver(t, func(*url.URL, *Upstream) error {
		if callbackCalls.Add(1) == 1 {
			return errors.New("temporary callback failure")
		}
		return nil
	})
	if _, err := resolver.GetUpstream(); err == nil {
		t.Fatal("first GetUpstream() error = nil, want failure")
	}
	if upstream, err := resolver.GetUpstream(); err != nil || upstream == nil {
		t.Fatalf("second GetUpstream() = (%p, %v), want successful upstream", upstream, err)
	}
	if got := initCalls.Load(); got != 2 {
		t.Fatalf("initializer calls = %d, want 2", got)
	}
	if got := callbackCalls.Load(); got != 2 {
		t.Fatalf("callback calls = %d, want 2", got)
	}
}

func testUpstreamResolver(t *testing.T, callback func(*url.URL, *Upstream) error) *UpstreamResolver {
	t.Helper()
	raw, err := url.Parse("udp://192.0.2.53:53")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return &UpstreamResolver{
		Raw:                raw,
		Network:            "udp",
		FinishInitCallback: callback,
	}
}

func testUpstream(raw *url.URL) *Upstream {
	return &Upstream{
		Scheme:   UpstreamScheme_UDP,
		Hostname: raw.Hostname(),
		Port:     53,
	}
}

func TestUpstreamResolverUsesFixedInitializationTimeout(t *testing.T) {
	original := newUpstreamFunc
	t.Cleanup(func() {
		newUpstreamFunc = original
	})

	deadline := make(chan time.Time, 1)
	newUpstreamFunc = func(ctx context.Context, raw *url.URL, _ string) (*Upstream, error) {
		value, ok := ctx.Deadline()
		if !ok {
			t.Fatal("initializer context has no deadline")
		}
		deadline <- value
		return testUpstream(raw), nil
	}

	before := time.Now()
	resolver := testUpstreamResolver(t, func(*url.URL, *Upstream) error { return nil })
	if _, err := resolver.GetUpstream(); err != nil {
		t.Fatalf("GetUpstream(): %v", err)
	}
	got := <-deadline
	if got.Before(before.Add(9*time.Second)) || got.After(before.Add(11*time.Second)) {
		t.Fatalf("initializer deadline = %v, want about 10 seconds after %v", got, before)
	}
}
