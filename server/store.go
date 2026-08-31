/*
 * MIT License
 *
 * Copyright (c) 2022-2026 Anton Stremovskyy <stremovskyy@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package server

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var (
	ErrClientNotFound = errors.New("orionis server: client not found")
	ErrUnauthorized   = errors.New("orionis server: unauthorized client")
)

type ClientStore interface {
	FindClient(ctx context.Context, id string) (Client, error)
}

type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]Client
}

// MemoryStore creates an in-memory client store.
//
// Deprecated: use NewMemoryClientStore.
func MemoryStore(clients ...Client) *MemoryClientStore {
	return NewMemoryClientStore(clients...)
}

func NewMemoryClientStore(clients ...Client) *MemoryClientStore {
	store := &MemoryClientStore{clients: make(map[string]Client, len(clients))}

	for _, client := range clients {
		store.Upsert(client)
	}

	return store
}

func (s *MemoryClientStore) Upsert(client Client) {
	client = client.Normalize()

	if client.ID == "" {
		return
	}

	s.mu.Lock()
	s.clients[client.ID] = cloneClient(client)
	s.mu.Unlock()
}

func (s *MemoryClientStore) FindClient(ctx context.Context, id string) (Client, error) {
	_ = ctx

	s.mu.RLock()
	client, ok := s.clients[strings.TrimSpace(id)]
	s.mu.RUnlock()

	if !ok || client.Disabled {
		return Client{}, ErrClientNotFound
	}

	return cloneClient(client), nil
}
