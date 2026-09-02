package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func unavailableCloudWorkerEndpoint(context.Context, string) (time.Duration, error) {
	return 0, errors.New("endpoint unreachable")
}

func TestCloudWorkerPlacementUsesFastestHTTPSMeasurementBeforeGeography(t *testing.T) {
	placement := newCloudWorkerPlacement("ap-northeast-1")
	var calls atomic.Int32
	allStarted := make(chan struct{})
	placement.probe = func(ctx context.Context, region string) (time.Duration, error) {
		if calls.Add(1) == 3 {
			close(allStarted)
		}
		select {
		case <-allStarted:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		return map[string]time.Duration{"ap-northeast-1": 100 * time.Millisecond, "us-west-1": 50 * time.Millisecond, "eu-west-3": 25 * time.Millisecond}[region], nil
	}
	placement.random = func(int) int { t.Error("random selection used after successful probe"); return 0 }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wait sync.WaitGroup
	for index := 0; index < 12; index++ {
		wait.Go(func() {
			region, err := placement.region(ctx)
			if err != nil || region != "eu-west-3" {
				t.Errorf("region=%q err=%v", region, err)
			}
		})
	}
	wait.Wait()
	if calls.Load() != 3 {
		t.Fatalf("concurrent proposal probes=%d, want exactly three", calls.Load())
	}
}

func TestCloudWorkerPlacementSkipsFailedEndpointAndCachesChoice(t *testing.T) {
	placement := newCloudWorkerPlacement("")
	placement.probe = func(_ context.Context, region string) (time.Duration, error) {
		if region == "eu-west-3" {
			return time.Millisecond, errors.New("TLS failure")
		}
		if region == "us-west-1" {
			return 20 * time.Millisecond, nil
		}
		return 30 * time.Millisecond, nil
	}
	region, err := placement.region(context.Background())
	if err != nil || region != "us-west-1" {
		t.Fatalf("region=%q err=%v", region, err)
	}
	placement.probe = func(context.Context, string) (time.Duration, error) {
		t.Error("cached selection re-probed")
		return 0, nil
	}
	if repeated, err := placement.region(context.Background()); err != nil || repeated != region {
		t.Fatalf("repeated=%q err=%v", repeated, err)
	}
}

func TestCloudWorkerPlacementGeographicFallbackUsesGreatCircleDistance(t *testing.T) {
	for host, expected := range map[string]string{
		"ap-northeast-1": "ap-northeast-1", "us-west-1": "us-west-1", "eu-west-3": "eu-west-3",
		"ap-south-1": "ap-northeast-1", "ap-south-2": "ap-northeast-1", "sa-east-1": "eu-west-3",
		"us-east-1": "us-west-1", "ca-west-1": "us-west-1", "mx-central-1": "us-west-1",
		"af-south-1": "eu-west-3", "me-central-1": "eu-west-3", "eu-central-1": "eu-west-3",
		"ap-east-2": "ap-northeast-1", "ap-southeast-5": "ap-northeast-1", "ap-southeast-6": "ap-northeast-1", "ap-southeast-7": "ap-northeast-1",
	} {
		t.Run(host, func(t *testing.T) {
			placement := newCloudWorkerPlacement(host)
			placement.probe = unavailableCloudWorkerEndpoint
			placement.random = func(int) int { t.Error("known host used random fallback"); return 0 }
			if region, err := placement.region(context.Background()); err != nil || region != expected {
				t.Fatalf("region=%q want=%q err=%v", region, expected, err)
			}
		})
	}
}

func TestCloudWorkerPlacementUnknownHostUsesUniformThreeWayFallback(t *testing.T) {
	for _, host := range []string{"", "zz-unknown-1", "us-gov-west-1"} {
		for index, expected := range []string{"ap-northeast-1", "us-west-1", "eu-west-3"} {
			placement := newCloudWorkerPlacement(host)
			placement.probe = unavailableCloudWorkerEndpoint
			calls := 0
			placement.random = func(size int) int {
				calls++
				if size != 3 {
					t.Errorf("random bound=%d", size)
				}
				return index
			}
			for attempt := 0; attempt < 2; attempt++ {
				if region, err := placement.region(context.Background()); err != nil || region != expected {
					t.Fatalf("host=%q region=%q err=%v", host, region, err)
				}
			}
			if calls != 1 {
				t.Fatalf("fallback re-randomized %d times", calls)
			}
		}
	}
}

func TestCloudWorkerPlacementCanceledAttemptDoesNotFreezeFallback(t *testing.T) {
	placement := newCloudWorkerPlacement("")
	started := make(chan struct{}, 3)
	placement.probe = func(ctx context.Context, _ string) (time.Duration, error) {
		started <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := placement.region(ctx); done <- err }()
	for range 3 {
		<-started
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	placement.probe = unavailableCloudWorkerEndpoint
	placement.random = func(int) int { return 2 }
	if region, err := placement.region(context.Background()); err != nil || region != "eu-west-3" {
		t.Fatalf("retry region=%q err=%v", region, err)
	}
}

func TestCloudWorkerPlacementExpiresMeasurementsAndReprobes(t *testing.T) {
	placement := newCloudWorkerPlacement("")
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	placement.now = func() time.Time { return now }
	var calls atomic.Int32
	preferred := "ap-northeast-1"
	placement.probe = func(_ context.Context, region string) (time.Duration, error) {
		calls.Add(1)
		if region == preferred {
			return time.Millisecond, nil
		}
		return 20 * time.Millisecond, nil
	}
	if region, err := placement.region(context.Background()); err != nil || region != preferred {
		t.Fatalf("initial=%q err=%v", region, err)
	}
	preferred = "us-west-1"
	now = now.Add(cloudWorkerPlacementTTL - time.Nanosecond)
	if region, err := placement.region(context.Background()); err != nil || region != "ap-northeast-1" || calls.Load() != 3 {
		t.Fatalf("unexpired=%q calls=%d err=%v", region, calls.Load(), err)
	}
	now = now.Add(time.Nanosecond)
	if region, err := placement.region(context.Background()); err != nil || region != preferred || calls.Load() != 6 {
		t.Fatalf("expired=%q calls=%d err=%v", region, calls.Load(), err)
	}
}
