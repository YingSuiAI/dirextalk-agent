package coreexecutionv2

import (
	"time"
)

// NewServiceWithProviderInterfaces is the production composition constructor.
// Callers pass only typed adapters that have already bound the existing Core
// Workload/AWS SSM/ECS services.  A nil interface route stays nil (and is not
// published as part of the capability), while Ready is the explicit startup
// proof for the adapter set.
func NewServiceWithProviderInterfaces(store Store, interfaces ProviderInterfaces, now func() time.Time) (*Service, error) {
	typed := AdaptProviderInterfaces(interfaces)
	if typed.Ready == nil {
		typed.Ready = func() bool { return false }
	}
	return NewService(Config{Store: store, Typed: typed, Ready: typed.Ready, Now: now})
}
