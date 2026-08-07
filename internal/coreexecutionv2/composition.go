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
	return NewServiceWithProviderInterfacesAndCloudWorker(store, interfaces, nil, now)
}

// NewServiceWithProviderInterfacesAndCloudWorker is the complete production
// constructor for the published Execution V2 surface. The Cloud Worker port
// is kept separate from generic provider interfaces because it reads and
// cancels records in the strongly typed Cloud Worker authority.
func NewServiceWithProviderInterfacesAndCloudWorker(store Store, interfaces ProviderInterfaces, cloudWorker CloudWorkerExecutionPort, now func() time.Time) (*Service, error) {
	return NewServiceWithProviderInterfacesCloudWorkerAndRunLifecycle(store, interfaces, cloudWorker, nil, now)
}

// NewServiceWithProviderInterfacesCloudWorkerAndRunLifecycle composes the
// PostgreSQL transaction owner for generic runs separately from the neutral
// Execution V2 record store. Production PostgreSQL deliberately uses distinct
// implementations for those authorities.
func NewServiceWithProviderInterfacesCloudWorkerAndRunLifecycle(store Store, interfaces ProviderInterfaces, cloudWorker CloudWorkerExecutionPort, runs GenericRunLifecycle, now func() time.Time) (*Service, error) {
	typed := AdaptProviderInterfaces(interfaces)
	return NewService(Config{Store: store, Typed: typed, CloudWorker: cloudWorker, RunLifecycle: runs, Ready: func() bool { return true }, Now: now})
}
