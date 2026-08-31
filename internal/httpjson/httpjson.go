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

package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrTrailingData = errors.New("response body contains trailing JSON data")

func Read(r io.Reader, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, errors.New("response body is nil")
	}

	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}

	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("response body too large: limit=%d bytes", maxBytes)
	}

	return raw, nil
}

func Decode(r io.Reader, maxBytes int64, dst any) error {
	raw, err := Read(r, maxBytes)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%w: %v", ErrTrailingData, err)
		}

		return ErrTrailingData
	}

	return nil
}
