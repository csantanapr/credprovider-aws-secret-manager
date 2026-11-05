// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"container/list"
	"context"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CacheConfig sizes the in-process payload cache. Authorization always runs
// before the cache is consulted, so a cached value is never a bypass.
type CacheConfig struct {
	// StageTTL bounds how long a stage reference (AWSCURRENT, ...) is served
	// from memory: after a rotation the old value is injected for at most this
	// long. Zero disables caching.
	StageTTL time.Duration
	// VersionTTL is for version-ID references, whose payload never changes.
	VersionTTL time.Duration
	// NegativeTTL caches NotFound/PermissionDenied/FailedPrecondition/
	// InvalidArgument answers, so a broken policy cannot burn the account's
	// GetSecretValue quota. Unavailable and DeadlineExceeded are never cached.
	NegativeTTL time.Duration
	// MaxEntries bounds memory: a value is at most 64 KiB.
	MaxEntries int
}

type cacheKey struct {
	// scope is the atespace when IAM enforces per-atespace access (role
	// chaining), so one atespace's fetch never serves another's request.
	// Empty otherwise.
	scope                                   string
	account, region, name, stage, versionID string
}

func keyFor(scope string, r SecretRef) cacheKey {
	return cacheKey{scope, r.Account, r.Region, r.Name, r.Stage, r.VersionID}
}

type entry struct {
	key     cacheKey
	val     []byte
	err     error
	expires time.Time
	elem    *list.Element
}

type flight struct {
	done chan struct{}
	val  []byte
	err  error
}

// Cache is an LRU of secret payloads with per-key request coalescing.
type Cache struct {
	cfg          CacheConfig
	fetchTimeout time.Duration
	now          func() time.Time

	mu       sync.Mutex
	entries  map[cacheKey]*entry
	lru      *list.List // front = most recent
	inflight map[cacheKey]*flight
}

func NewCache(cfg CacheConfig, fetchTimeout time.Duration) *Cache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	return &Cache{cfg: cfg, fetchTimeout: fetchTimeout, now: time.Now,
		entries: map[cacheKey]*entry{}, lru: list.New(), inflight: map[cacheKey]*flight{}}
}

// Get returns the cached payload for k, or calls fetch once for all concurrent
// callers. fetch runs on a context detached from the first caller's
// cancellation, bounded by the fetch timeout, so one impatient caller does not
// fail the others waiting on the same key.
func (c *Cache) Get(ctx context.Context, k cacheKey, fetch func(context.Context) ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		if c.now().Before(e.expires) {
			c.lru.MoveToFront(e.elem)
			c.mu.Unlock()
			return e.val, e.err
		}
		c.removeLocked(e)
	}
	f, ok := c.inflight[k]
	if !ok {
		f = &flight{done: make(chan struct{})}
		c.inflight[k] = f
		go c.run(ctx, k, f, fetch)
	}
	c.mu.Unlock()

	select {
	case <-f.done:
		return f.val, f.err
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

func (c *Cache) run(ctx context.Context, k cacheKey, f *flight, fetch func(context.Context) ([]byte, error)) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
	defer cancel()
	f.val, f.err = fetch(fctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inflight, k)
	// Cache before waking waiters, so a caller's next request is a hit.
	if ttl := c.ttlFor(k, f.err); ttl > 0 {
		e := &entry{key: k, val: f.val, err: f.err, expires: c.now().Add(ttl)}
		e.elem = c.lru.PushFront(e)
		c.entries[k] = e
		for c.lru.Len() > c.cfg.MaxEntries {
			c.removeLocked(c.lru.Back().Value.(*entry))
		}
	}
	close(f.done)
}

func (c *Cache) ttlFor(k cacheKey, err error) time.Duration {
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound, codes.PermissionDenied, codes.FailedPrecondition, codes.InvalidArgument:
			return c.cfg.NegativeTTL
		default:
			return 0
		}
	}
	if k.versionID != "" {
		return c.cfg.VersionTTL
	}
	return c.cfg.StageTTL
}

func (c *Cache) removeLocked(e *entry) {
	c.lru.Remove(e.elem)
	delete(c.entries, e.key)
}

// Len is the number of cached entries (for tests and metrics).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
