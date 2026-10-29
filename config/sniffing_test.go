/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSniffingConfig(t *testing.T) {
	for _, tt := range []struct {
		name  string
		rules string
		valid bool
	}{
		{name: "empty", valid: true},
		{name: "domain", rules: "domain(suffix: push.apple.com) -> skip", valid: true},
		{name: "address", rules: "dip(91.105.192.0/23, '2001:67c:4e8::/48') -> skip", valid: true},
		{name: "alias", rules: "ip(192.0.2.1) -> skip", valid: true},
		{name: "mixed", rules: "domain(full: example.com) && !dip(192.0.2.0/24) -> skip", valid: true},
		{name: "geodata", rules: "domain(geosite: private) -> skip\ndip(geoip: private) -> skip", valid: true},
		{name: "wrong action", rules: "domain(example.com) -> direct"},
		{name: "action parameters", rules: "domain(example.com) -> skip(mark: 1)"},
		{name: "source address", rules: "sip(192.0.2.1) -> skip"},
		{name: "port", rules: "dport(443) -> skip"},
		{name: "empty domain", rules: "domain() -> skip"},
		{name: "empty address", rules: "dip() -> skip"},
		{name: "fallback", rules: "fallback: skip"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nrouting { fallback: direct }\nsniffing {\n" + tt.rules + "\n}")
			if err != nil {
				if tt.valid {
					t.Fatalf("parse configuration: %v", err)
				}
				return
			}
			_, err = New(sections)
			if (err == nil) != tt.valid {
				t.Fatalf("New() error = %v, want valid = %v", err, tt.valid)
			}
		})
	}
}

func TestSniffingConfigRoundTrip(t *testing.T) {
	sections, err := config_parser.Parse(`
		global {}
		routing { fallback: direct }
		sniffing {
			domain(suffix: push.apple.com, keyword: example) -> skip
			dip(91.105.192.0/23, '2001:67c:4e8::/48') -> skip
			domain(full: example.com) && !ip(192.0.2.0/24) -> skip
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	marshaller := Marshaller{IndentSpace: 4}
	if err := marshaller.MarshalSection("sniffing", reflect.ValueOf(conf.Sniffing), 0); err != nil {
		t.Fatal(err)
	}
	marshaled := marshaller.Bytes()
	sections, err = config_parser.Parse("global {}\nrouting { fallback: direct }\n" + string(marshaled))
	if err != nil {
		t.Fatal(err)
	}
	got, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Sniffing, conf.Sniffing) {
		t.Fatalf("sniffing rules changed after round trip:\n%s", marshaled)
	}
}

func TestSniffingConfigOptional(t *testing.T) {
	sections, err := config_parser.Parse("global {}\nrouting { fallback: direct }")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Sniffing.Rules) != 0 {
		t.Fatalf("unexpected default sniffing rules: %v", conf.Sniffing.Rules)
	}
}

func TestSniffingConfigInclude(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "entry.dae")
	files := map[string]string{
		entry:                           "include { extra.dae }\nglobal {}\nrouting { fallback: direct }\nsniffing { domain(example.com) -> skip }",
		filepath.Join(dir, "extra.dae"): "sniffing { dip(192.0.2.0/24) -> skip }",
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sections, _, err := NewMerger(entry).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Sniffing.Rules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(conf.Sniffing.Rules))
	}
}

func TestSniffingConfigOutline(t *testing.T) {
	for _, section := range ExportOutline("test").Structure {
		if section.Mapping == "sniffing" {
			if section.Required || !strings.Contains(section.Desc, "skip") || len(section.Structure) != 1 {
				t.Fatalf("unexpected sniffing outline: %+v", section)
			}
			return
		}
	}
	t.Fatal("sniffing section missing from outline")
}
