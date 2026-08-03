package githubapp

import "context"

type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

type ResolverPrivateKeySource struct {
	resolver SecretResolver
}

func NewResolverPrivateKeySource(
	resolver SecretResolver,
) (*ResolverPrivateKeySource, error) {
	if resolver == nil {
		return nil, ErrUnavailable
	}
	return &ResolverPrivateKeySource{resolver: resolver}, nil
}

func (source *ResolverPrivateKeySource) MaterializeGitHubAppPrivateKey(
	ctx context.Context,
	reference string,
	use func([]byte) error,
) error {
	if source == nil ||
		source.resolver == nil ||
		ctx == nil ||
		!secretRefPattern.MatchString(reference) ||
		use == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, err := source.resolver.ResolveSecret(ctx, reference)
	if err != nil || len(value) == 0 {
		clear(value)
		return ErrUnavailable
	}
	defer clear(value)
	if err := use(value); err != nil {
		return ErrUnavailable
	}
	return nil
}

var _ PrivateKeySource = (*ResolverPrivateKeySource)(nil)
