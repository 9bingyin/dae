/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package cmd

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestArchiveSysdump(t *testing.T) {
	sourceDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(sourceDir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"routing.txt":           "default via 192.0.2.1\n",
		"nested/interfaces.txt": "eth0\n",
		"empty.txt":             "",
	}
	for name, contents := range want {
		if err := os.WriteFile(filepath.Join(sourceDir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	filename := filepath.Join(t.TempDir(), "sysdump.tar.gz")
	if err := archiveSysdump(sourceDir, filename); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("archive permissions = %o, want 600", mode)
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	got := make(map[string]string)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		contents, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		got[header.Name] = string(contents)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("archive contents = %v, want %v", got, want)
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		t.Fatalf("read gzip trailer: %v", err)
	}
}

func TestArchiveSysdumpDoesNotOverwrite(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "existing.tar.gz")
	want := "existing archive"
	if err := os.WriteFile(filename, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}
	if err := archiveSysdump(t.TempDir(), filename); !errors.Is(err, os.ErrExist) {
		t.Fatalf("error = %v, want os.ErrExist", err)
	}
	got, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("existing archive = %q, want %q", got, want)
	}
}

func TestArchiveSysdumpMissingSource(t *testing.T) {
	sourceDir := filepath.Join(t.TempDir(), "missing")
	filename := filepath.Join(t.TempDir(), "sysdump.tar.gz")
	if err := archiveSysdump(sourceDir, filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want os.ErrNotExist", err)
	}
}
