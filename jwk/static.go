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

package jwk

import (
	"context"
	"errors"
	"fmt"
)

type StaticBuilder struct {
	set Set
}

func Static(keys ...Key) *StaticBuilder {
	return (&StaticBuilder{}).Keys(keys...)
}

func (b *StaticBuilder) Key(key Key) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set.Keys = append(b.set.Keys, key)

	return b
}

func (b *StaticBuilder) Keys(keys ...Key) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set.Keys = append(b.set.Keys, keys...)

	return b
}

func (b *StaticBuilder) Set(set Set) *StaticBuilder {
	if b == nil {
		return nil
	}

	b.set = set

	return b
}

func (b *StaticBuilder) Build() (*StaticProvider, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil static builder")
	}

	return NewStaticProvider(b.set)
}

func (b *StaticBuilder) Must() *StaticProvider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

type StaticProvider struct {
	keys map[string]decodedKey
}

func NewStaticProvider(set Set) (*StaticProvider, error) {
	keys, err := decodeSet(set)
	if err != nil {
		if errors.Is(err, errNoKeys) {
			return nil, errors.New("static jwks has no keys")
		}

		return nil, err
	}

	return &StaticProvider{keys: keys}, nil
}

func (p *StaticProvider) Key(ctx context.Context, kid string, alg string) (any, error) {
	_ = ctx

	key, ok := p.keys[kid]

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	return key.forAlgorithm(kid, alg)
}
