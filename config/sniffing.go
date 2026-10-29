/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package config

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type Sniffing struct {
	Rules []*config_parser.RoutingRule `mapstructure:"_"`
}

// Validate checks the sniffing subset of routing syntax without changing it.
func (s *Sniffing) Validate() error {
	if s == nil {
		return nil
	}
	for i, rule := range s.Rules {
		if err := validateSniffingRule(rule); err != nil {
			return fmt.Errorf("sniffing rule %d: %w", i+1, err)
		}
	}
	return nil
}

func validateSniffingRule(rule *config_parser.RoutingRule) error {
	if rule == nil || len(rule.AndFunctions) == 0 {
		return fmt.Errorf("expected at least one domain or destination IP predicate")
	}
	if rule.Outbound.Name != "skip" || rule.Outbound.Not || len(rule.Outbound.Params) != 0 {
		return fmt.Errorf("action must be skip without parameters or negation")
	}
	for _, f := range rule.AndFunctions {
		if f == nil {
			return fmt.Errorf("nil predicate")
		}
		if f.Name != consts.Function_Domain && f.Name != consts.Function_Ip && f.Name != "dip" {
			return fmt.Errorf("unsupported predicate %q", f.Name)
		}
		if len(f.Params) == 0 {
			return fmt.Errorf("predicate %q requires parameters", f.Name)
		}
		for _, p := range f.Params {
			if p == nil || p.Val == "" || len(p.AndFunctions) != 0 || len(p.Annotation) != 0 {
				return fmt.Errorf("predicate %q requires nonempty plain parameters", f.Name)
			}
			validKey := false
			if f.Name == consts.Function_Domain {
				switch p.Key {
				case "", "domain", "contains", "full", "suffix", "keyword", "regex", "geosite", "ext":
					validKey = true
				}
			} else {
				switch p.Key {
				case "", "geoip", "ext":
					validKey = true
				}
			}
			if !validKey {
				return fmt.Errorf("unsupported parameter key %q for %q", p.Key, f.Name)
			}
			if p.Key == "ext" {
				file, code, ok := strings.Cut(p.Val, ":")
				if !ok || file == "" || code == "" {
					return fmt.Errorf("predicate %q ext parameter must be file:code", f.Name)
				}
			}
		}
	}
	return nil
}
