/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func sniffingRulesForTest(t *testing.T, text string) []*config_parser.RoutingRule {
	t.Helper()
	sections, err := config_parser.Parse("global {}\nrouting {\n" + text + "\n}")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf.Routing.Rules
}

func sniffingLogForTest() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func sniffingMatcherForTest(t *testing.T, text string) *SniffingMatcher {
	t.Helper()
	m, err := NewSniffingMatcher(sniffingLogForTest(), sniffingRulesForTest(t, text), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSniffingMatcherEmpty(t *testing.T) {
	empty, err := NewSniffingMatcher(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (*config.Sniffing)(nil).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*SniffingMatcher{nil, {}, empty} {
		if got, err := m.SkipIP(netip.AddrPort{}); err != nil || got {
			t.Fatalf("empty SkipIP = %v, %v", got, err)
		}
		if got, err := m.SkipDomain(netip.AddrPort{}, "example.com"); err != nil || got {
			t.Fatalf("empty SkipDomain = %v, %v", got, err)
		}
	}
	m := sniffingMatcherForTest(t, "!domain(full:example.com) -> skip")
	if got, err := m.SkipDomain(netip.AddrPort{}, ""); err != nil || got {
		t.Fatalf("empty domain = %v, %v", got, err)
	}
}

func TestSniffingMatcherDomainRoutingSemantics(t *testing.T) {
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	for _, tt := range []struct {
		name, predicate string
		hits, misses    []string
	}{
		{"full", "domain(full:example.com)", []string{"example.com", "EXAMPLE.COM."}, []string{"www.example.com", "badexample.com", "example.com.evil"}},
		{"suffix", "domain(suffix:example.com)", []string{"example.com", "a.b.example.com", "WWW.Example.COM."}, []string{"badexample.com", "example.com.evil"}},
		{"dot suffix", "domain(suffix:.example.com)", []string{"www.example.com"}, []string{"example.com", "badexample.com"}},
		{"default suffix", "domain(example.com)", []string{"example.com", "www.example.com"}, []string{"badexample.com"}},
		{"domain alias", "domain(domain:example.com)", []string{"www.example.com"}, []string{"badexample.com"}},
		{"keyword", "domain(keyword:needle)", []string{"needle.test", "aNEEDLEb.test."}, []string{"need.test"}},
		{"contains alias", "domain(contains:needle)", []string{"aneedleb.test"}, []string{"need.test"}},
		{"regex", `domain(regex:'^api[0-9]+\.example\.com$')`, []string{"api12.example.com", "API1.EXAMPLE.COM."}, []string{"api.example.com", "xapi1.example.com", "api1.example.com.evil"}},
		{"mixed keys OR", "domain(full:exact.test, suffix:suffix.test, keyword:needle)", []string{"exact.test", "x.suffix.test", "aneedleb.test"}, []string{"x.exact.test", "badsuffix.test"}},
		{"negated mixed keys", "!domain(full:exact.test, suffix:suffix.test)", []string{"other.test"}, []string{"exact.test", "x.suffix.test"}},
		// Patterns, unlike the queried domain, are not lowercased by routing.
		{"uppercase regex pattern", `domain(regex:'^EXAMPLE\.COM$')`, nil, []string{"EXAMPLE.COM", "example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := sniffingRulesForTest(t, tt.predicate+" -> skip")
			m, err := NewSniffingMatcher(sniffingLogForTest(), rules, nil)
			if err != nil {
				t.Fatal(err)
			}
			optimized, err := routing.ApplyRulesOptimizers(rules, &routing.AliasOptimizer{}, &routing.DeduplicateParamsOptimizer{})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := NewRoutingMatcherBuilder(sniffingLogForTest(), optimized, map[string]uint8{"skip": 1, "continue": 0}, nil, "continue")
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := builder.BuildUserspace()
			if err != nil {
				t.Fatal(err)
			}
			check := func(domain string, want bool) {
				t.Helper()
				got, err := m.SkipDomain(dst, domain)
				if err != nil || got != want {
					t.Fatalf("SkipDomain(%q) = %v, %v; want %v", domain, got, err, want)
				}
				addr := dst.Addr().As16()
				out, _, _, err := baseline.Match(addr[:], addr[:], 0, dst.Port(), consts.IpVersion_X, 0, domain, [16]byte{}, 0, addr[:])
				if err != nil || got != (out == 1) {
					t.Fatalf("routing parity for %q: outbound = %d, err = %v", domain, out, err)
				}
			}
			for _, domain := range tt.hits {
				check(domain, true)
			}
			for _, domain := range tt.misses {
				check(domain, false)
			}
			if got, err := m.SkipIP(dst); err != nil || got {
				t.Fatalf("domain predicate ran before sniffing: %v, %v", got, err)
			}
		})
	}
}

func TestSniffingMatcherIP(t *testing.T) {
	for _, predicate := range []string{"dip(10.0.0.0/8, '2001:db8::/32')", "ip(10.0.0.0/8, '2001:db8::/32')", "ip('::ffff:10.0.0.0/104', '2001:db8::/32')"} {
		t.Run(predicate, func(t *testing.T) {
			m := sniffingMatcherForTest(t, predicate+" -> skip")
			for _, tt := range []struct {
				addr string
				want bool
			}{
				{"10.0.0.0:1", true}, {"10.255.255.255:65535", true}, {"11.0.0.0:443", false},
				{"[::ffff:10.2.3.4]:443", true}, {"[::ffff:11.0.0.1]:443", false},
				{"[2001:db8::]:443", true}, {"[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:443", true},
				{"[2001:db9::]:443", false},
			} {
				dst := netip.MustParseAddrPort(tt.addr)
				if got, err := m.SkipIP(dst); err != nil || got != tt.want {
					t.Errorf("SkipIP(%s) = %v, %v; want %v", dst, got, err, tt.want)
				}
				if got, err := m.SkipDomain(dst, "example.com"); err != nil || got {
					t.Errorf("IP predicate leaked into post plane: %v, %v", got, err)
				}
			}
		})
	}
}

func TestSniffingMatcherBareIP(t *testing.T) {
	m := sniffingMatcherForTest(t, "dip(192.0.2.1, '2001:db8::1') -> skip")
	for _, tt := range []struct {
		addr string
		want bool
	}{
		{"192.0.2.1:443", true},
		{"192.0.2.2:443", false},
		{"[2001:db8::1]:443", true},
		{"[2001:db8::2]:443", false},
	} {
		if got, err := m.SkipIP(netip.MustParseAddrPort(tt.addr)); err != nil || got != tt.want {
			t.Errorf("SkipIP(%s) = %v, %v; want %v", tt.addr, got, err, tt.want)
		}
	}
}

func TestSniffingMatcherLogicAndStages(t *testing.T) {
	for _, tt := range []struct {
		name, rules, dst, domain string
		pre, post                bool
	}{
		{"IP AND hit", "ip(10.0.0.0/8) && !ip(10.1.0.0/16) -> skip", "10.2.0.1:443", "x.test", true, false},
		{"IP AND miss", "ip(10.0.0.0/8) && !ip(10.1.0.0/16) -> skip", "10.1.0.1:443", "x.test", false, false},
		{"mixed delayed", "dip(10.0.0.0/8) && domain(example.com) -> skip", "10.0.0.1:443", "example.com", false, true},
		{"mixed reverse order", "domain(example.com) && dip(10.0.0.0/8) -> skip", "10.0.0.1:443", "example.com", false, true},
		{"mixed IP miss", "domain(example.com) && dip(10.0.0.0/8) -> skip", "192.0.2.1:443", "example.com", false, false},
		{"mixed domain miss", "dip(10.0.0.0/8) && domain(example.com) -> skip", "10.0.0.1:443", "else.test", false, false},
		{"negated domain delayed", "dip(10.0.0.0/8) && !domain(example.com) -> skip", "10.0.0.1:443", "else.test", false, true},
		{"empty negated domain", "!domain(example.com) -> skip", "10.0.0.1:443", "", false, false},
		{"domain AND", "domain(suffix:example.com) && !domain(full:example.com) -> skip", "10.0.0.1:443", "www.example.com", false, true},
		{"domain AND miss", "domain(suffix:example.com) && !domain(full:example.com) -> skip", "10.0.0.1:443", "example.com", false, false},
		{"negated domain rules stay OR", "!domain(full:a.test) -> skip\n!domain(full:b.test) -> skip", "10.0.0.1:443", "a.test", false, true},
		{"negated IP rules stay OR", "!ip(10.0.0.0/8) -> skip\n!ip(192.0.2.0/24) -> skip", "10.0.0.1:443", "a.test", true, false},
		{"stages independent", "domain(a.test) -> skip\nip(10.0.0.0/8) -> skip", "10.0.0.1:443", "a.test", true, true},
		{"stages reversed", "ip(10.0.0.0/8) -> skip\ndomain(a.test) -> skip", "10.0.0.1:443", "a.test", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := sniffingMatcherForTest(t, tt.rules)
			dst := netip.MustParseAddrPort(tt.dst)
			if got, err := m.SkipIP(dst); err != nil || got != tt.pre {
				t.Fatalf("pre = %v, %v; want %v", got, err, tt.pre)
			}
			if got, err := m.SkipDomain(dst, tt.domain); err != nil || got != tt.post {
				t.Fatalf("post = %v, %v; want %v", got, err, tt.post)
			}
		})
	}
}

func TestSniffingMatcherRejectsInvalidRules(t *testing.T) {
	for _, text := range []string{
		"domain(example.com) -> direct", "domain(example.com) -> continue", "domain(example.com) -> skip(mark:1)",
		"domain(example.com) -> skip(must)", "port(443) -> skip", "sip(10.0.0.0/8) -> skip", "dport(443) -> skip",
		"domain(bad:example.com) -> skip", "ip(bad:10.0.0.0/8) -> skip",
		"domain(geoip:xx) -> skip", "ip(geosite:xx) -> skip", "domain(ext:missingcolon) -> skip",
		"domain(ext:':xx') -> skip", "ip(ext:'fixture:') -> skip", "ip(not-an-ip) -> skip", "ip(10.0.0.0/33) -> skip",
		"ip('2001:db8::/129') -> skip", "domain(regex:'[') -> skip", "domain(full:'') -> skip",
	} {
		t.Run(text, func(t *testing.T) {
			m, err := NewSniffingMatcher(sniffingLogForTest(), sniffingRulesForTest(t, text), nil)
			if err == nil || m != nil {
				t.Fatalf("invalid rule accepted: matcher=%v, error=%v", m, err)
			}
			if errors.Unwrap(err) == nil {
				t.Fatalf("missing error context: %v", err)
			}
		})
	}
	for _, mutate := range []func(*config_parser.RoutingRule){
		func(r *config_parser.RoutingRule) { r.Outbound.Not = true },
		func(r *config_parser.RoutingRule) { r.AndFunctions = nil },
		func(r *config_parser.RoutingRule) { r.AndFunctions[0] = nil },
		func(r *config_parser.RoutingRule) { r.AndFunctions[0].Params = nil },
		func(r *config_parser.RoutingRule) { r.AndFunctions[0].Name = "ip"; r.AndFunctions[0].Params = nil },
		func(r *config_parser.RoutingRule) { r.AndFunctions[0].Params[0] = nil },
		func(r *config_parser.RoutingRule) {
			r.AndFunctions[0].Params[0].AndFunctions = []*config_parser.Function{{Name: "skip"}}
		},
		func(r *config_parser.RoutingRule) {
			r.AndFunctions[0].Params[0].Annotation = []*config_parser.Param{{Val: "annotation"}}
		},
	} {
		rules := sniffingRulesForTest(t, "domain(example.com) -> skip")
		mutate(rules[0])
		if _, err := NewSniffingMatcher(nil, rules, nil); err == nil {
			t.Fatal("invalid AST accepted")
		}
	}
	if _, err := NewSniffingMatcher(nil, []*config_parser.RoutingRule{nil}, nil); err == nil {
		t.Fatal("nil rule accepted")
	}
	m := sniffingMatcherForTest(t, "ip(10.0.0.0/8) -> skip\ndomain(example.com) -> skip")
	if got, err := m.SkipIP(netip.AddrPort{}); err == nil || got {
		t.Fatalf("invalid destination: %v, %v", got, err)
	}
	if got, err := m.SkipDomain(netip.AddrPort{}, "example.com"); err == nil || got {
		t.Fatalf("invalid domain destination: %v, %v", got, err)
	}
}

func TestSniffingMatcherMatchSetLimit(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		wantError  bool
	}{
		{"boundary", strings.Repeat("domain(full:example.com) -> skip\n", consts.MaxMatchSetLen-1), false},
		{"overflow", strings.Repeat("domain(full:example.com) -> skip\n", consts.MaxMatchSetLen), true},
		{"IP overflow", strings.Repeat("ip(10.0.0.0/8) -> skip\n", consts.MaxMatchSetLen), true},
		{"expanded keys overflow", strings.Repeat("domain(full:a.test, suffix:b.test) -> skip\n", consts.MaxMatchSetLen/2), true},
		{"independent planes", strings.Repeat("ip(10.0.0.0/8) -> skip\ndomain(full:example.com) -> skip\n", consts.MaxMatchSetLen/2), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSniffingMatcher(sniffingLogForTest(), sniffingRulesForTest(t, tt.text), nil)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, want error %v", err, tt.wantError)
			}
			if err != nil && !strings.Contains(err.Error(), "match set length") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSniffingMatcherReadOnly(t *testing.T) {
	rules := sniffingRulesForTest(t, "dip(10.0.0.0/8,10.0.0.0/8) -> skip\ndomain(domain:example.com,domain:example.com) -> skip")
	before, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewSniffingMatcher(nil, rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("constructor changed input rules")
	}
	rules[0].AndFunctions[0].Params[0].Val = "192.0.2.0/24"
	rules[1].AndFunctions[0].Params[0].Val = "else.test"
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 32 {
				dst := netip.MustParseAddrPort("10.0.0.1:443")
				if got, err := m.SkipIP(dst); err != nil || !got {
					t.Errorf("concurrent pre = %v, %v", got, err)
				}
				if got, err := m.SkipDomain(dst, "WWW.EXAMPLE.COM."); err != nil || !got {
					t.Errorf("concurrent post = %v, %v", got, err)
				}
			}
		})
	}
	wg.Wait()
}

func TestSniffingMatcherGeodata(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", dir)
	writeDat := func(name string, data proto.Message) {
		t.Helper()
		encoded, err := proto.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".dat"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDat("geosite", &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "XX", Domain: []*geodata.Domain{
		{Type: geodata.Domain_Full, Value: "full.test", Attribute: []*geodata.Domain_Attribute{{Key: "selected"}}},
		{Type: geodata.Domain_RootDomain, Value: "suffix.test"},
		{Type: geodata.Domain_Plain, Value: "needle"},
		{Type: geodata.Domain_Regex, Value: `^api[0-9]+\.test$`},
	}}, {CountryCode: "EMPTY"}}})
	writeDat("geoip", &geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "XX", Cidr: []*geodata.CIDR{
		{Ip: []byte{10, 0, 0, 0}, Prefix: 8},
		{Ip: netip.MustParseAddr("2001:db8::").AsSlice(), Prefix: 32},
	}}, {CountryCode: "EMPTY"}}})
	finder := assets.NewLocationFinder([]string{dir})
	for _, tt := range []struct {
		name, rules, dst, domain string
		pre, post                bool
	}{
		{"geoip v4", "dip(geoip:xx) -> skip", "10.1.0.1:443", "full.test", true, false},
		{"geoip v6", "ip(geoip:xx) -> skip", "[2001:db8::1]:443", "full.test", true, false},
		{"geoip mapped", "ip(geoip:xx) -> skip", "[::ffff:10.1.0.1]:443", "full.test", true, false},
		{"geoip miss", "ip(geoip:xx) -> skip", "192.0.2.1:443", "full.test", false, false},
		{"geosite full", "domain(geosite:xx) -> skip", "10.0.0.1:443", "FULL.TEST.", false, true},
		{"geosite suffix", "domain(geosite:xx) -> skip", "10.0.0.1:443", "a.suffix.test", false, true},
		{"geosite keyword", "domain(geosite:xx) -> skip", "10.0.0.1:443", "aneedleb.test", false, true},
		{"geosite regex", "domain(geosite:xx) -> skip", "10.0.0.1:443", "api12.test", false, true},
		{"geosite attr hit", "domain(geosite:xx@selected) -> skip", "10.0.0.1:443", "full.test", false, true},
		{"geosite attr miss", "domain(geosite:xx@selected) -> skip", "10.0.0.1:443", "suffix.test", false, false},
		{"ext mixed", "domain(ext:'geosite:xx') && dip(ext:'geoip:xx') -> skip", "10.0.0.1:443", "full.test", false, true},
		{"empty site", "domain(geosite:empty) -> skip", "10.0.0.1:443", "full.test", false, false},
		{"empty site AND", "domain(geosite:empty) && ip(10.0.0.0/8) -> skip", "10.0.0.1:443", "full.test", false, false},
		{"negated empty site", "!domain(geosite:empty) -> skip", "10.0.0.1:443", "full.test", false, true},
		{"empty attribute", "!domain(geosite:xx@absent) -> skip", "10.0.0.1:443", "full.test", false, true},
		{"empty IP", "ip(geoip:empty) -> skip", "10.0.0.1:443", "full.test", false, false},
		{"negated empty IP", "!ip(geoip:empty) -> skip", "10.0.0.1:443", "full.test", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := sniffingRulesForTest(t, tt.rules)
			before, err := json.Marshal(rules)
			if err != nil {
				t.Fatal(err)
			}
			m, err := NewSniffingMatcher(sniffingLogForTest(), rules, finder)
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(rules)
			if err != nil || string(before) != string(after) {
				t.Fatalf("geodata modified rules: %v", err)
			}
			dst := netip.MustParseAddrPort(tt.dst)
			if got, err := m.SkipIP(dst); err != nil || got != tt.pre {
				t.Fatalf("pre = %v, %v; want %v", got, err, tt.pre)
			}
			if got, err := m.SkipDomain(dst, tt.domain); err != nil || got != tt.post {
				t.Fatalf("post = %v, %v; want %v", got, err, tt.post)
			}
		})
	}
	for _, text := range []string{"domain(geosite:missing) -> skip", "ip(ext:'__sniffing_missing_fixture__:xx') -> skip"} {
		if _, err := NewSniffingMatcher(sniffingLogForTest(), sniffingRulesForTest(t, text), finder); err == nil {
			t.Fatalf("missing geodata accepted: %s", text)
		}
	}
}
