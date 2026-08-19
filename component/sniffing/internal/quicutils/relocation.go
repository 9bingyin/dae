/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"errors"
	"fmt"
)

var (
	ErrUnknownFrameType = errors.New("unknown frame type")
	ErrOutOfRange       = errors.New("index out of range")
)

type Locator interface {
	Range(i, j int) ([]byte, error)
	Slice(i, j int) (Locator, error)
	At(i int) (byte, error)
	Len() int
	Bytes() ([]byte, error)
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) ([]byte, error) {
	if i < 0 || j < i || j > len(l) {
		return nil, fmt.Errorf("range [%d,%d): %w", i, j, ErrOutOfRange)
	}
	return l[i:j], nil
}

func (l BuiltinBytesLocator) At(i int) (byte, error) {
	if i < 0 || i >= len(l) {
		return 0, fmt.Errorf("index %d: %w", i, ErrOutOfRange)
	}
	return l[i], nil
}

func (l BuiltinBytesLocator) Slice(i, j int) (Locator, error) {
	if i < 0 || j < i || j > len(l) {
		return nil, fmt.Errorf("slice [%d,%d): %w", i, j, ErrOutOfRange)
	}
	return l[i:j], nil
}

func (l BuiltinBytesLocator) Len() int {
	return len(l)
}

func (l BuiltinBytesLocator) Bytes() ([]byte, error) {
	return l, nil
}

var _ Locator = BuiltinBytesLocator{}
