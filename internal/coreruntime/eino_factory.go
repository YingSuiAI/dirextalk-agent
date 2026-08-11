package coreruntime

import (
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func adaptClientFactory(factory ClientFactory) ClientFactory {
	if factory == nil {
		factory = func(profile coremodel.Profile) (coremodel.Client, error) {
			return coremodel.NewClient(profile, coremodel.WithStreamIdleTimeout(ConversationModelStreamIdleTimeout))
		}
	}
	return func(profile coremodel.Profile) (coremodel.Client, error) {
		delegate, err := factory(profile)
		if err != nil {
			return nil, err
		}
		return coremodel.NewEinoClient(delegate)
	}
}
