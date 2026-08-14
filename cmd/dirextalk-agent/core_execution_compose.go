package main

import "github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"

type coreExecutionV2Composition struct{ domain *coreexecutionv2.Service }

func composeCoreExecutionV2(port coreexecutionv2.CloudWorkerExecutionPort) (*coreExecutionV2Composition, error) {
	if port == nil {
		return nil, nil
	}
	domain, err := coreexecutionv2.NewService(port)
	if err != nil {
		return nil, err
	}
	return &coreExecutionV2Composition{domain: domain}, nil
}
