package roothelper

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
)

type RootOwnedInstalledStateInspector struct {
	volumes map[string]bootstrap.InstalledVolumeEvidenceV1
	reader  bootstrap.VolumeStateReader
}

func NewRootOwnedInstalledStateInspector(state bootstrap.InstalledStateV1) *RootOwnedInstalledStateInspector {
	volumes := make(map[string]bootstrap.InstalledVolumeEvidenceV1, len(state.Volumes))
	for _, evidence := range state.Volumes {
		volumes[evidence.Name] = evidence
	}
	return &RootOwnedInstalledStateInspector{volumes: volumes, reader: bootstrap.NewLinuxVolumeStateReader()}
}

func (inspector *RootOwnedInstalledStateInspector) VerifyVolume(ctx context.Context, volume installer.VolumeV1) error {
	if inspector == nil || inspector.reader == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	evidence, ok := inspector.volumes[volume.Name]
	if !ok || evidence.AttachmentDevice != volume.DeviceName || evidence.SizeBytes != uint64(volume.SizeGiB)<<30 ||
		evidence.FileSystem != "ext4" || evidence.MountPath != volume.MountPath || evidence.ReadOnly != volume.ReadOnly {
		return ErrUnavailable
	}
	observed, err := inspector.reader.Observe(ctx, evidence.VolumeID, volume.MountPath)
	if err != nil || observed.SizeBytes != evidence.SizeBytes || observed.FileSystem != evidence.FileSystem ||
		observed.FileSystemUUID != evidence.FileSystemUUID || observed.MountPath != evidence.MountPath || observed.ReadOnly != evidence.ReadOnly {
		return ErrUnavailable
	}
	return nil
}

var _ InstalledStateInspector = (*RootOwnedInstalledStateInspector)(nil)
