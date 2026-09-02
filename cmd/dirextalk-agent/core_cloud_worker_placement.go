package main

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"
)

var cloudWorkerRegions = [...]string{"ap-northeast-1", "us-west-1", "eu-west-3"}

const cloudWorkerPlacementTimeout = 3 * time.Second
const cloudWorkerPlacementTTL = 5 * time.Minute

func supportedCloudWorkerRegion(region string) bool {
	for _, supported := range cloudWorkerRegions {
		if region == supported {
			return true
		}
	}
	return false
}

// Placement is lazy and briefly cached: verified new proposals share fresh
// measurements, while durable bindings retain their own allowlisted Region.
type cloudWorkerPlacement struct {
	hostRegion string
	probe      func(context.Context, string) (time.Duration, error)
	random     func(int) int
	now        func() time.Time
	mu         sync.Mutex
	selected   string
	expiresAt  time.Time
	selecting  chan struct{}
}

func newCloudWorkerPlacement(hostRegion string) *cloudWorkerPlacement {
	return &cloudWorkerPlacement{hostRegion: hostRegion, probe: probeCloudWorkerEndpoint, random: rand.IntN, now: time.Now}
}

func (placement *cloudWorkerPlacement) region(ctx context.Context) (string, error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		placement.mu.Lock()
		if placement.selected != "" && placement.now().Before(placement.expiresAt) {
			selected := placement.selected
			placement.mu.Unlock()
			return selected, nil
		}
		if pending := placement.selecting; pending != nil {
			placement.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-pending:
				continue
			}
		}
		placement.selecting = make(chan struct{})
		placement.mu.Unlock()
		selected, err := placement.choose(ctx)
		placement.mu.Lock()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			placement.selected = selected
			placement.expiresAt = placement.now().Add(cloudWorkerPlacementTTL)
		}
		close(placement.selecting)
		placement.selecting = nil
		placement.mu.Unlock()
		return selected, err
	}
}

func (placement *cloudWorkerPlacement) choose(ctx context.Context) (string, error) {
	probeContext, cancel := context.WithTimeout(ctx, cloudWorkerPlacementTimeout)
	defer cancel()
	type measurement struct {
		region   string
		duration time.Duration
		err      error
	}
	results := make(chan measurement, len(cloudWorkerRegions))
	for _, region := range cloudWorkerRegions {
		go func(region string) {
			duration, err := placement.probe(probeContext, region)
			results <- measurement{region, duration, err}
		}(region)
	}
	var selected string
	var fastest time.Duration
measurements:
	for remaining := len(cloudWorkerRegions); remaining > 0; remaining-- {
		select {
		case result := <-results:
			if result.err == nil && result.duration >= 0 && (selected == "" || result.duration < fastest || result.duration == fastest && result.region < selected) {
				selected, fastest = result.region, result.duration
			}
		case <-probeContext.Done():
			break measurements
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if selected != "" {
		return selected, nil
	}
	if nearest := nearestCloudWorkerRegion(placement.hostRegion); nearest != "" {
		return nearest, nil
	}
	return cloudWorkerRegions[placement.random(len(cloudWorkerRegions))], nil
}

// Measure a fresh direct HTTPS/TLS connection and response headers, not Worker
// latency. EC2's unauthenticated 4xx response is valid connectivity evidence.
// Do not send credentials, follow redirects, use ambient proxies, or reuse TLS.
func probeCloudWorkerEndpoint(ctx context.Context, region string) (time.Duration, error) {
	if !supportedCloudWorkerRegion(region) {
		return 0, errors.New("unsupported Worker endpoint")
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: cloudWorkerPlacementTimeout}).DialContext,
		TLSHandshakeTimeout: cloudWorkerPlacementTimeout, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: cloudWorkerPlacementTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://ec2."+region+".amazonaws.com/", nil)
	if err != nil {
		return 0, err
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return time.Since(started), nil
}

type regionLocation struct{ latitude, longitude float64 }

// Approximate host metro coordinates, not AZ locations or latency estimates.
// Explicit commercial-Region entries ensure new/unknown Region names fall back
// to random placement rather than silently guessing from a name prefix.
var cloudWorkerRegionLocations = map[string]regionLocation{
	"us-east-1": {39.04, -77.49}, "us-east-2": {39.96, -83.00},
	"us-west-1": {37.34, -121.89}, "us-west-2": {45.52, -122.68},
	"af-south-1": {-33.92, 18.42},
	"ap-east-1":  {22.32, 114.17}, "ap-east-2": {25.03, 121.56},
	"ap-south-1": {19.08, 72.88}, "ap-south-2": {17.39, 78.49},
	"ap-northeast-1": {35.68, 139.69}, "ap-northeast-2": {37.57, 126.98}, "ap-northeast-3": {34.69, 135.50},
	"ap-southeast-1": {1.35, 103.82}, "ap-southeast-2": {-33.87, 151.21}, "ap-southeast-3": {-6.21, 106.85},
	"ap-southeast-4": {-37.81, 144.96}, "ap-southeast-5": {3.14, 101.69}, "ap-southeast-6": {-36.85, 174.76}, "ap-southeast-7": {13.76, 100.50},
	"ca-central-1": {45.50, -73.57}, "ca-west-1": {51.05, -114.07},
	"eu-central-1": {50.11, 8.68}, "eu-central-2": {47.38, 8.54},
	"eu-west-1": {53.35, -6.26}, "eu-west-2": {51.51, -0.13}, "eu-west-3": {48.86, 2.35},
	"eu-north-1": {59.33, 18.07}, "eu-south-1": {45.46, 9.19}, "eu-south-2": {41.65, -0.89},
	"il-central-1": {32.09, 34.78}, "me-south-1": {26.22, 50.59}, "me-central-1": {25.20, 55.27},
	"mx-central-1": {20.59, -100.39}, "sa-east-1": {-23.55, -46.63},
}

func nearestCloudWorkerRegion(hostRegion string) string {
	host, known := cloudWorkerRegionLocations[hostRegion]
	if !known {
		return ""
	}
	selected, closest := "", math.Inf(1)
	for _, region := range cloudWorkerRegions {
		target := cloudWorkerRegionLocations[region]
		toRadians := math.Pi / 180
		latitude, targetLatitude := host.latitude*toRadians, target.latitude*toRadians
		cosine := math.Sin(latitude)*math.Sin(targetLatitude) + math.Cos(latitude)*math.Cos(targetLatitude)*math.Cos((host.longitude-target.longitude)*toRadians)
		distance := math.Acos(math.Max(-1, math.Min(1, cosine)))
		if distance < closest {
			selected, closest = region, distance
		}
	}
	return selected
}
