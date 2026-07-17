package awsprovider

import (
	"context"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

var (
	volumeAttachmentInstancePattern = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	volumeAttachmentVolumePattern   = regexp.MustCompile(`^vol-[0-9a-f]{8,17}$`)
	volumeAttachmentDevicePattern   = regexp.MustCompile(`^/dev/sd[f-p]$`)
)

type VolumeAttachmentState string

const (
	VolumeAttachmentStateAttaching VolumeAttachmentState = "attaching"
	VolumeAttachmentStateAttached  VolumeAttachmentState = "attached"
	VolumeAttachmentStateDetaching VolumeAttachmentState = "detaching"
	VolumeAttachmentStateDetached  VolumeAttachmentState = "detached"
)

// VolumeAttachmentSpecV1 is the complete immutable input a caller persists
// before invoking a mutation. This provider deliberately owns no persistence
// and does not claim that an intent is durable on the caller's behalf.
type VolumeAttachmentSpecV1 struct {
	IntentID   string `json:"intent_id"`
	Region     string `json:"region"`
	InstanceID string `json:"instance_id"`
	VolumeID   string `json:"volume_id"`
	DeviceName string `json:"device_name"`
}

type VolumeAttachmentObservationV1 struct {
	IntentID   string                `json:"intent_id"`
	Region     string                `json:"region"`
	InstanceID string                `json:"instance_id"`
	VolumeID   string                `json:"volume_id"`
	DeviceName string                `json:"device_name"`
	State      VolumeAttachmentState `json:"state"`
	Exists     bool                  `json:"exists"`
	ObservedAt time.Time             `json:"observed_at"`
}

// VolumeAttachmentProvider is intentionally narrower than the resource
// provider. Callers must persist VolumeAttachmentSpecV1 before either mutation.
type VolumeAttachmentProvider interface {
	AttachVolume(context.Context, VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error)
	DetachVolume(context.Context, VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error)
	ReadBackVolumeAttachment(context.Context, VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error)
}

type VolumeAttachmentEC2API interface {
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	AttachVolume(context.Context, *ec2.AttachVolumeInput, ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(context.Context, *ec2.DetachVolumeInput, ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
}

type AWSVolumeAttachmentProvider struct {
	client       VolumeAttachmentEC2API
	region       string
	now          func() time.Time
	pollInterval time.Duration
}

type VolumeAttachmentProviderOption func(*AWSVolumeAttachmentProvider) error

func WithVolumeAttachmentPollInterval(interval time.Duration) VolumeAttachmentProviderOption {
	return func(provider *AWSVolumeAttachmentProvider) error {
		if interval <= 0 || interval > time.Minute {
			return ErrInvalidRequest
		}
		provider.pollInterval = interval
		return nil
	}
}

func NewVolumeAttachmentProvider(client VolumeAttachmentEC2API, region string, now func() time.Time, options ...VolumeAttachmentProviderOption) (*AWSVolumeAttachmentProvider, error) {
	if client == nil || !sdkRegionPattern.MatchString(region) || now == nil {
		return nil, ErrInvalidRequest
	}
	provider := &AWSVolumeAttachmentProvider{client: client, region: region, now: now, pollInterval: 5 * time.Second}
	for _, option := range options {
		if option == nil || option(provider) != nil {
			return nil, ErrInvalidRequest
		}
	}
	return provider, nil
}

// NewVolumeAttachmentProviderFromConfig is the production AWS SDK adapter.
// It does not load ambient credentials; callers supply an already-scoped config.
func NewVolumeAttachmentProviderFromConfig(config aws.Config, options ...VolumeAttachmentProviderOption) (*AWSVolumeAttachmentProvider, error) {
	if !sdkRegionPattern.MatchString(config.Region) || config.Credentials == nil {
		return nil, ErrInvalidRequest
	}
	return NewVolumeAttachmentProvider(ec2.NewFromConfig(config), config.Region, time.Now, options...)
}

var _ VolumeAttachmentProvider = (*AWSVolumeAttachmentProvider)(nil)

func (provider *AWSVolumeAttachmentProvider) AttachVolume(ctx context.Context, spec VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error) {
	if err := provider.validate(spec); err != nil {
		return VolumeAttachmentObservationV1{}, err
	}
	current, err := provider.ReadBackVolumeAttachment(ctx, spec)
	if err != nil {
		return VolumeAttachmentObservationV1{}, err
	}
	if current.Exists {
		switch current.State {
		case VolumeAttachmentStateAttached:
			return current, nil
		case VolumeAttachmentStateAttaching:
			return provider.waitFor(ctx, spec, VolumeAttachmentStateAttached)
		default:
			return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
		}
	}
	_, mutationErr := provider.client.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device: aws.String(spec.DeviceName), InstanceId: aws.String(spec.InstanceID), VolumeId: aws.String(spec.VolumeID),
	})
	if mutationErr != nil {
		recovered, readErr := provider.ReadBackVolumeAttachment(ctx, spec)
		if readErr == nil && recovered.Exists {
			switch recovered.State {
			case VolumeAttachmentStateAttached:
				return recovered, nil
			case VolumeAttachmentStateAttaching:
				return provider.waitFor(ctx, spec, VolumeAttachmentStateAttached)
			}
		}
		return VolumeAttachmentObservationV1{}, providerError(ctx, mutationErr)
	}
	return provider.waitFor(ctx, spec, VolumeAttachmentStateAttached)
}

func (provider *AWSVolumeAttachmentProvider) DetachVolume(ctx context.Context, spec VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error) {
	if err := provider.validate(spec); err != nil {
		return VolumeAttachmentObservationV1{}, err
	}
	current, err := provider.ReadBackVolumeAttachment(ctx, spec)
	if err != nil {
		return VolumeAttachmentObservationV1{}, err
	}
	if !current.Exists {
		return current, nil
	}
	if current.State == VolumeAttachmentStateDetaching {
		return provider.waitFor(ctx, spec, VolumeAttachmentStateDetached)
	}
	if current.State != VolumeAttachmentStateAttached {
		return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
	}
	_, mutationErr := provider.client.DetachVolume(ctx, &ec2.DetachVolumeInput{
		Device: aws.String(spec.DeviceName), InstanceId: aws.String(spec.InstanceID), VolumeId: aws.String(spec.VolumeID), Force: aws.Bool(false),
	})
	if mutationErr != nil {
		recovered, readErr := provider.ReadBackVolumeAttachment(ctx, spec)
		if readErr == nil {
			if !recovered.Exists {
				return recovered, nil
			}
			if recovered.State == VolumeAttachmentStateDetaching {
				return provider.waitFor(ctx, spec, VolumeAttachmentStateDetached)
			}
		}
		return VolumeAttachmentObservationV1{}, providerError(ctx, mutationErr)
	}
	return provider.waitFor(ctx, spec, VolumeAttachmentStateDetached)
}

func (provider *AWSVolumeAttachmentProvider) ReadBackVolumeAttachment(ctx context.Context, spec VolumeAttachmentSpecV1) (VolumeAttachmentObservationV1, error) {
	if err := provider.validate(spec); err != nil {
		return VolumeAttachmentObservationV1{}, err
	}
	output, err := provider.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{spec.VolumeID}})
	if err != nil {
		return VolumeAttachmentObservationV1{}, providerError(ctx, err)
	}
	base := provider.observation(spec)
	if output == nil || len(output.Volumes) != 1 || aws.ToString(output.Volumes[0].VolumeId) != spec.VolumeID {
		return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
	}
	volume := output.Volumes[0]
	if len(volume.Attachments) == 0 {
		if volume.State != ec2types.VolumeStateAvailable {
			return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
		}
		base.State = VolumeAttachmentStateDetached
		return base, nil
	}
	if len(volume.Attachments) != 1 {
		return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
	}
	attachment := volume.Attachments[0]
	if aws.ToString(attachment.InstanceId) != spec.InstanceID || aws.ToString(attachment.VolumeId) != spec.VolumeID ||
		aws.ToString(attachment.Device) != spec.DeviceName {
		return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
	}
	switch attachment.State {
	case ec2types.VolumeAttachmentStateAttaching:
		base.State = VolumeAttachmentStateAttaching
	case ec2types.VolumeAttachmentStateAttached:
		base.State = VolumeAttachmentStateAttached
	case ec2types.VolumeAttachmentStateDetaching:
		base.State = VolumeAttachmentStateDetaching
	default:
		return VolumeAttachmentObservationV1{}, ErrReadBackMismatch
	}
	base.Exists = true
	return base, nil
}

func (provider *AWSVolumeAttachmentProvider) validate(spec VolumeAttachmentSpecV1) error {
	intentID, err := uuid.Parse(spec.IntentID)
	if provider == nil || provider.client == nil || provider.now == nil || err != nil || intentID == uuid.Nil ||
		intentID.String() != spec.IntentID || spec.Region != provider.region ||
		!volumeAttachmentInstancePattern.MatchString(spec.InstanceID) ||
		!volumeAttachmentVolumePattern.MatchString(spec.VolumeID) ||
		!volumeAttachmentDevicePattern.MatchString(spec.DeviceName) {
		return ErrInvalidRequest
	}
	return nil
}

func (provider *AWSVolumeAttachmentProvider) observation(spec VolumeAttachmentSpecV1) VolumeAttachmentObservationV1 {
	return VolumeAttachmentObservationV1{
		IntentID: spec.IntentID, Region: spec.Region, InstanceID: spec.InstanceID,
		VolumeID: spec.VolumeID, DeviceName: spec.DeviceName, ObservedAt: provider.now().UTC(),
	}
}

func (provider *AWSVolumeAttachmentProvider) waitFor(ctx context.Context, spec VolumeAttachmentSpecV1, expected VolumeAttachmentState) (VolumeAttachmentObservationV1, error) {
	ticker := time.NewTicker(provider.pollInterval)
	defer ticker.Stop()
	for {
		current, err := provider.ReadBackVolumeAttachment(ctx, spec)
		if err != nil {
			return VolumeAttachmentObservationV1{}, err
		}
		if current.State == expected && (expected == VolumeAttachmentStateDetached || current.Exists) {
			return current, nil
		}
		select {
		case <-ctx.Done():
			return VolumeAttachmentObservationV1{}, providerError(ctx, ctx.Err())
		case <-ticker.C:
		}
	}
}
