/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, 9bingyin
 */

package control

import (
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func runtimeStatsBaseTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func orderedRuntimeHistory(s *runtimeStats) []runtimeBucket {
	history := make([]runtimeBucket, 0, len(s.history))
	history = append(history, s.history[s.historyHead:]...)
	return append(history, s.history[:s.historyHead]...)
}

func TestRuntimeStatsEmptySnapshot(t *testing.T) {
	stats := &runtimeStats{}
	now := runtimeStatsBaseTime()
	snapshot := stats.snapshot(0, 0, -1, -1, now)
	want := RuntimeStatsSnapshot{
		UpdatedAt: now,
		Samples:   []RuntimeTrafficSample{{Timestamp: now}},
	}
	if !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("empty snapshot = %+v, want %+v", snapshot, want)
	}
	if len(stats.history) != 0 {
		t.Fatalf("empty snapshot created history: %+v", stats.history)
	}
}

func TestRuntimeStatsPartialAndBoundaryRates(t *testing.T) {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	stats.record(250, 500, base.Add(100*time.Millisecond))
	first := stats.snapshot(2, 3, 0, 0, base.Add(125*time.Millisecond))
	if first.UploadRate != 2000 || first.DownloadRate != 4000 || first.UploadTotal != 250 || first.DownloadTotal != 500 {
		t.Fatalf("first snapshot = %+v", first)
	}
	if first.ActiveConnections != 2 || first.UDPSessions != 3 || len(first.Samples) != 1 {
		t.Fatalf("first snapshot metadata = %+v", first)
	}
	stats.record(750, 1500, base.Add(350*time.Millisecond))
	partial := stats.snapshot(2, 3, 0, 0, base.Add(375*time.Millisecond))
	if partial.UploadRate != 2666 || partial.DownloadRate != 5333 || partial.UploadTotal != 1000 || partial.DownloadTotal != 2000 {
		t.Fatalf("partial snapshot = %+v", partial)
	}
	want := []RuntimeTrafficSample{
		{Timestamp: base.Add(250 * time.Millisecond), UploadRate: 1000, DownloadRate: 2000},
		{Timestamp: base.Add(375 * time.Millisecond), UploadRate: 6000, DownloadRate: 12000},
	}
	if !reflect.DeepEqual(partial.Samples, want) {
		t.Fatalf("partial samples = %+v, want %+v", partial.Samples, want)
	}
	boundary := stats.snapshot(0, 0, 0, 0, base.Add(500*time.Millisecond))
	if boundary.UploadRate != 1333 || boundary.DownloadRate != 2666 {
		t.Fatalf("boundary rates = %d/%d", boundary.UploadRate, boundary.DownloadRate)
	}
}

func TestRuntimeStatsHistoryWrapAndWindow(t *testing.T) {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	count := maxRuntimeHistoryBuckets + 8
	for i := range count {
		stats.record(uint64(i+1), uint64(2*(i+1)), base.Add(time.Duration(i)*runtimeBucketDuration))
	}
	if len(stats.history) != maxRuntimeHistoryBuckets || cap(stats.history) != maxRuntimeHistoryBuckets {
		t.Fatalf("history len/cap = %d/%d", len(stats.history), cap(stats.history))
	}
	history := orderedRuntimeHistory(stats)
	for i, bucket := range history {
		value := uint64(i + 8)
		if bucket.UploadBytes != value || bucket.DownloadBytes != 2*value || !bucket.Timestamp.Equal(base.Add(time.Duration(i+8)*runtimeBucketDuration)) {
			t.Fatalf("history[%d] = %+v", i, bucket)
		}
	}
	now := stats.currentBucketStart.Add(125 * time.Millisecond)
	snapshot := stats.snapshot(7, 11, 1, 100, now)
	want := samplesFromBuckets(history[len(history)-4:])
	want = append(want, RuntimeTrafficSample{Timestamp: now, UploadRate: uint64(count) * 8, DownloadRate: uint64(count) * 16})
	if !reflect.DeepEqual(snapshot.Samples, want) {
		t.Fatalf("window samples = %+v, want %+v", snapshot.Samples, want)
	}
	if snapshot.UploadTotal != uint64(count*(count+1)/2) || snapshot.DownloadTotal != uint64(count*(count+1)) {
		t.Fatalf("totals = %d/%d", snapshot.UploadTotal, snapshot.DownloadTotal)
	}
	if snapshot.ActiveConnections != 7 || snapshot.UDPSessions != 11 {
		t.Fatalf("connection metadata = %+v", snapshot)
	}
}

func TestRuntimeStatsIdleGap(t *testing.T) {
	base := runtimeStatsBaseTime()
	for _, gap := range []time.Duration{time.Hour, time.Hour + runtimeBucketDuration, 24 * time.Hour} {
		t.Run(gap.String(), func(t *testing.T) {
			stats := &runtimeStats{}
			stats.record(20, 40, base.Add(-time.Second))
			stats.record(100, 200, base)
			target := base.Add(gap)
			stats.record(300, 600, target)
			history := orderedRuntimeHistory(stats)
			if len(history) != maxRuntimeHistoryBuckets {
				t.Fatalf("history length = %d", len(history))
			}
			for i, bucket := range history {
				wantUpload, wantDownload := uint64(0), uint64(0)
				if gap == time.Hour && i == 0 {
					wantUpload, wantDownload = 100, 200
				}
				wantTime := target.Add(time.Duration(i-maxRuntimeHistoryBuckets+1) * runtimeBucketDuration)
				if bucket.UploadBytes != wantUpload || bucket.DownloadBytes != wantDownload || bucket.Duration != runtimeBucketDuration || !bucket.Timestamp.Equal(wantTime) {
					t.Fatalf("history[%d] = %+v, want time %v bytes %d/%d", i, bucket, wantTime, wantUpload, wantDownload)
				}
			}
			snapshot := stats.snapshot(0, 0, 0, 0, target.Add(125*time.Millisecond))
			if snapshot.UploadTotal != 420 || snapshot.DownloadTotal != 840 || snapshot.UploadRate != 300 || snapshot.DownloadRate != 600 {
				t.Fatalf("snapshot after idle = %+v", snapshot)
			}
		})
	}
}

func TestRuntimeStatsSnapshotPeaksAndIsolation(t *testing.T) {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	for i, values := range [][2]uint64{{25, 200}, {250, 50}, {50, 75}, {200, 600}, {100, 10}} {
		stats.record(values[0], values[1], base.Add(time.Duration(i)*runtimeBucketDuration))
	}
	now := base.Add(1125 * time.Millisecond)
	snapshot := stats.snapshot(0, 0, 0, 2, now)
	want := []RuntimeTrafficSample{
		{Timestamp: base.Add(750 * time.Millisecond), UploadRate: 1000, DownloadRate: 800},
		{Timestamp: now, UploadRate: 800, DownloadRate: 2400},
	}
	if !reflect.DeepEqual(snapshot.Samples, want) || snapshot.UploadRate != 612 || snapshot.DownloadRate != 835 {
		t.Fatalf("snapshot = %+v, want samples %+v and rates 612/835", snapshot, want)
	}
	snapshot.Samples[0].UploadRate = 9999
	if got := stats.snapshot(0, 0, 0, 2, now); !reflect.DeepEqual(got.Samples, want) {
		t.Fatalf("snapshot mutation affected stats: %+v", got.Samples)
	}
	previous := stats.snapshot(0, 0, 0, 2, now)
	copyOfSamples := slices.Clone(previous.Samples)
	stats.record(1, 2, base.Add(24*time.Hour))
	if !reflect.DeepEqual(previous.Samples, copyOfSamples) {
		t.Fatalf("history mutation affected previous snapshot: %+v", previous.Samples)
	}
}

func TestRuntimeStatsBackwardsTime(t *testing.T) {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	stats.record(100, 200, base.Add(time.Second))
	stats.record(50, 100, base)
	if !stats.currentBucketStart.Equal(base.Add(time.Second)) || len(stats.history) != 0 || stats.currentUploadBytes != 150 || stats.currentDownloadBytes != 300 {
		t.Fatalf("backwards timestamp changed current bucket: %+v", stats)
	}
}

func TestRuntimeStatsWarmRolloverDoesNotAllocate(t *testing.T) {
	stats := &runtimeStats{}
	stats.record(1, 2, runtimeStatsBaseTime())
	stats.record(3, 4, runtimeStatsBaseTime().Add(time.Hour))
	allocations := testing.AllocsPerRun(100, func() {
		stats.record(5, 6, stats.currentBucketStart.Add(runtimeBucketDuration))
	})
	if allocations != 0 {
		t.Fatalf("warm rollover allocations = %v, want 0", allocations)
	}
}

func TestRuntimeStatsConcurrentRecordAndSnapshot(t *testing.T) {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for i := range 256 {
				stats.record(1, 2, base.Add(time.Duration(i)*runtimeBucketDuration))
			}
		})
	}
	group.Go(func() {
		for i := range 256 {
			stats.snapshot(0, 0, 30, 10, base.Add(time.Duration(i)*runtimeBucketDuration))
		}
	})
	group.Wait()
	snapshot := stats.snapshot(0, 0, 0, 0, base.Add(64*time.Second))
	if snapshot.UploadTotal != 1024 || snapshot.DownloadTotal != 2048 {
		t.Fatalf("concurrent totals = %d/%d", snapshot.UploadTotal, snapshot.DownloadTotal)
	}
}

func fullRuntimeStatsForBenchmark() *runtimeStats {
	base := runtimeStatsBaseTime()
	stats := &runtimeStats{}
	stats.record(1, 2, base)
	stats.record(1, 2, base.Add(time.Hour))
	return stats
}

func BenchmarkRuntimeStats(b *testing.B) {
	for _, gap := range []time.Duration{250 * time.Millisecond, time.Second, 10 * time.Second, 24 * time.Hour} {
		b.Run("FullHistoryAdvance"+gap.String(), func(b *testing.B) {
			stats := fullRuntimeStatsForBenchmark()
			b.ResetTimer()
			for b.Loop() {
				stats.record(1200, 0, stats.currentBucketStart.Add(gap))
			}
		})
	}
	b.Run("FullHistorySnapshot", func(b *testing.B) {
		stats := fullRuntimeStatsForBenchmark()
		now := stats.currentBucketStart.Add(125 * time.Millisecond)
		b.ResetTimer()
		for b.Loop() {
			stats.snapshot(1, 1, defaultRuntimeWindowSec, defaultRuntimeMaxPoints, now)
		}
	})
}
