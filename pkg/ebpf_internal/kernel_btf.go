/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package internal

import "github.com/cilium/ebpf/btf"

var kernelBTFCache = btf.NewCache()

// KernelBTFCache returns the process-wide BTF cache shared by all eBPF loads.
// cilium/ebpf v0.22 removed its implicit global kernel BTF cache, so callers
// should pass this cache through ebpf.CollectionOptions when loading multiple
// collections.
func KernelBTFCache() *btf.Cache {
	return kernelBTFCache
}

// LoadKernelSpec loads kernel BTF through the shared cache.
//
// Linux 7.1 BTF layout is supported by cilium/ebpf v0.22, so the old local
// header-stripping fallback for v0.21 is intentionally no longer needed.
func LoadKernelSpec() (*btf.Spec, error) {
	return kernelBTFCache.Kernel()
}
