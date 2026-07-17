package roothelper

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
)

func TestInstalledStateInspectorMatchesSignedVolumeToStableReadback(t *testing.T) {
	volume := installer.VolumeV1{Name: "knowledge", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge", SizeGiB: 40}
	evidence := bootstrap.InstalledVolumeEvidenceV1{
		Name: volume.Name, ResourceID: "77777777-7777-4777-8777-777777777777", VolumeID: "vol-0123456789abcdef0",
		AttachmentDevice: volume.DeviceName, ResolvedDevicePath: "/dev/nvme1n1", SizeBytes: 40 << 30,
		FileSystem: "ext4", FileSystemUUID: "11111111-2222-4333-8444-555555555555", MountPath: volume.MountPath,
	}
	reader := &fakeVolumeStateReader{observation: bootstrap.InstalledVolumeObservationV1{
		ResolvedDevicePath: "/dev/nvme3n1", SizeBytes: evidence.SizeBytes, FileSystem: evidence.FileSystem,
		FileSystemUUID: evidence.FileSystemUUID, MountPath: evidence.MountPath,
	}}
	inspector := &RootOwnedInstalledStateInspector{volumes: map[string]bootstrap.InstalledVolumeEvidenceV1{volume.Name: evidence}, reader: reader}
	if err := inspector.VerifyVolume(context.Background(), volume); err != nil {
		t.Fatal(err)
	}
	reader.observation.SizeBytes++
	if err := inspector.VerifyVolume(context.Background(), volume); err != ErrUnavailable {
		t.Fatalf("size drift error = %v", err)
	}
}

type fakeVolumeStateReader struct {
	observation bootstrap.InstalledVolumeObservationV1
	err         error
}

func (reader *fakeVolumeStateReader) Observe(context.Context, string, string) (bootstrap.InstalledVolumeObservationV1, error) {
	return reader.observation, reader.err
}
