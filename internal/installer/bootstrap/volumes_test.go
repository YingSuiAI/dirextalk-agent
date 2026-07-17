package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

func TestApprovedVolumeMaterializerFormatsBlankNitroVolumeOnceAndPersistsUUID(t *testing.T) {
	volume := testVolumeMount()
	host := newFakeVolumeHost(volume)
	materializer, err := NewVolumeMaterializer(host)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := materializer.Prepare(context.Background(), []VolumeMountV1{volume})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].VolumeID != volume.Source.VolumeID || evidence[0].FileSystemUUID != testVolumeUUID || evidence[0].SizeBytes != 40<<30 {
		t.Fatalf("installed evidence = %#v", evidence)
	}
	if host.mkfsCalls != 1 || host.mountCalls != 1 || host.fstabWrites != 1 {
		t.Fatalf("first prepare calls = mkfs:%d mount:%d fstab:%d", host.mkfsCalls, host.mountCalls, host.fstabWrites)
	}
	wantLine := "UUID=" + testVolumeUUID + " /srv/knowledge ext4 defaults,nofail 0 2 # dirextalk-volume=" + volume.Source.VolumeID
	if !bytes.Contains(host.fstab, []byte(wantLine)) {
		t.Fatalf("fstab did not bind the approved UUID: %q", host.fstab)
	}
	if _, err := materializer.Prepare(context.Background(), []VolumeMountV1{volume}); err != nil {
		t.Fatal(err)
	}
	if host.mkfsCalls != 1 || host.mountCalls != 1 || host.fstabWrites != 1 {
		t.Fatalf("replay repeated destructive work = mkfs:%d mount:%d fstab:%d", host.mkfsCalls, host.mountCalls, host.fstabWrites)
	}
}

func TestApprovedVolumeMaterializerNeverReformatsExistingExt4(t *testing.T) {
	volume := testVolumeMount()
	volume.Approved.ReadOnly = true
	host := newFakeVolumeHost(volume)
	host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "ext4", UUID: testVolumeUUID}}}
	materializer, _ := NewVolumeMaterializer(host)
	if _, err := materializer.Prepare(context.Background(), []VolumeMountV1{volume}); err != nil {
		t.Fatal(err)
	}
	if host.mkfsCalls != 0 || !reflect.DeepEqual(host.mountModes, []bool{true}) || !bytes.Contains(host.fstab, []byte("defaults,nofail,ro")) {
		t.Fatalf("existing ext4 was not mounted read-only without format: mkfs=%d modes=%v fstab=%q", host.mkfsCalls, host.mountModes, host.fstab)
	}
}

func TestVolumeStateReaderResolvesStableVolumeIdentityAcrossDeviceRenumbering(t *testing.T) {
	volume := testVolumeMount()
	host := newFakeVolumeHost(volume)
	host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "ext4", UUID: testVolumeUUID}}}
	host.mount = MountObservationV1{Found: true, DevicePath: "/dev/nvme3n1", TargetPath: volume.Approved.MountPath, FileSystem: "ext4", UUID: testVolumeUUID, Options: []string{"rw"}}
	host.devices[0].Path = "/dev/nvme3n1"
	reader, err := NewVolumeStateReader(host)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := reader.Observe(context.Background(), volume.Source.VolumeID, volume.Approved.MountPath)
	if err != nil || observed.ResolvedDevicePath != "/dev/nvme3n1" || observed.SizeBytes != 40<<30 || observed.FileSystemUUID != testVolumeUUID || observed.ReadOnly {
		t.Fatalf("observed volume = %#v err=%v", observed, err)
	}
}

func TestVolumeStateReaderRejectsIdentityAndMountDrift(t *testing.T) {
	volume := testVolumeMount()
	for name, mutate := range map[string]func(*fakeVolumeHost){
		"wrong serial":     func(host *fakeVolumeHost) { host.devices[0].Serial = "vol0ffffffffffffffff" },
		"uuid drift":       func(host *fakeVolumeHost) { host.probe.FileSystems[0].UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
		"filesystem drift": func(host *fakeVolumeHost) { host.probe.FileSystems[0].Type = "xfs" },
		"source drift":     func(host *fakeVolumeHost) { host.mount.DevicePath = "/dev/nvme9n1" },
		"mount missing":    func(host *fakeVolumeHost) { host.mount.Found = false },
	} {
		t.Run(name, func(t *testing.T) {
			host := newFakeVolumeHost(volume)
			host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "ext4", UUID: testVolumeUUID}}}
			host.mount = MountObservationV1{Found: true, DevicePath: "/dev/nvme1n1", TargetPath: volume.Approved.MountPath, FileSystem: "ext4", UUID: testVolumeUUID, Options: []string{"rw"}}
			mutate(host)
			reader, _ := NewVolumeStateReader(host)
			if _, err := reader.Observe(context.Background(), volume.Source.VolumeID, volume.Approved.MountPath); !errors.Is(err, ErrMaterialize) {
				t.Fatalf("drift error = %v", err)
			}
		})
	}
}

func TestApprovedVolumeMaterializerFailsClosedBeforeFormattingUnsafeDevice(t *testing.T) {
	tests := map[string]func(*fakeVolumeHost, *VolumeMountV1){
		"wrong volume serial":            func(host *fakeVolumeHost, _ *VolumeMountV1) { host.devices[0].Serial = "vol0ffffffffffffffff" },
		"volume is too small":            func(host *fakeVolumeHost, _ *VolumeMountV1) { host.devices[0].SizeBytes = 39 << 30 },
		"volume is larger than approved": func(host *fakeVolumeHost, _ *VolumeMountV1) { host.devices[0].SizeBytes = 41 << 30 },
		"candidate is root":              func(host *fakeVolumeHost, _ *VolumeMountV1) { host.devices[0].MountPoints = []string{"/"} },
		"partitioned candidate": func(host *fakeVolumeHost, _ *VolumeMountV1) {
			host.devices = append(host.devices, BlockDeviceV1{Path: "/dev/nvme1n1p1", ParentPath: "/dev/nvme1n1", Type: "part", SizeBytes: 40 << 30})
		},
		"unknown filesystem": func(host *fakeVolumeHost, _ *VolumeMountV1) {
			host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "xfs", UUID: testVolumeUUID}}}
		},
		"multiple signatures": func(host *fakeVolumeHost, _ *VolumeMountV1) {
			host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "ext4", UUID: testVolumeUUID}, {Type: "ext4", UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}}
		},
		"partition signature": func(host *fakeVolumeHost, _ *VolumeMountV1) { host.probe = SignatureProbeV1{HasOther: true} },
		"reserved mount":      func(_ *fakeVolumeHost, volume *VolumeMountV1) { volume.Approved.MountPath = "/etc/service" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			volume := testVolumeMount()
			host := newFakeVolumeHost(volume)
			mutate(host, &volume)
			materializer, _ := NewVolumeMaterializer(host)
			if _, err := materializer.Prepare(context.Background(), []VolumeMountV1{volume}); !errors.Is(err, ErrMaterialize) {
				t.Fatalf("unsafe volume error = %v", err)
			}
			if host.mkfsCalls != 0 || host.mountCalls != 0 || host.fstabWrites != 0 {
				t.Fatalf("unsafe volume caused mutation: mkfs=%d mount=%d fstab=%d", host.mkfsCalls, host.mountCalls, host.fstabWrites)
			}
		})
	}
}

const testVolumeUUID = "11111111-2222-4333-8444-555555555555"

func testVolumeMount() VolumeMountV1 {
	return VolumeMountV1{
		Source: VolumeSourceV1{
			SchemaVersion: VolumeSourceSchemaV1, Name: "knowledge", ResourceID: "77777777-7777-4777-8777-777777777777",
			VolumeID: "vol-0123456789abcdef0", DeviceName: "/dev/sdf",
		},
		Approved: installer.VolumeV1{
			Name: "knowledge", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge", Persistent: true,
			Disposition: "delete_with_deployment", SizeGiB: 40,
		},
	}
}

type fakeVolumeHost struct {
	devices     []BlockDeviceV1
	probe       SignatureProbeV1
	mount       MountObservationV1
	fstab       []byte
	mkfsCalls   int
	mountCalls  int
	fstabWrites int
	mountModes  []bool
}

func newFakeVolumeHost(volume VolumeMountV1) *fakeVolumeHost {
	return &fakeVolumeHost{
		devices: []BlockDeviceV1{{Path: "/dev/nvme1n1", Type: "disk", Serial: "vol0123456789abcdef0", SizeBytes: 40 << 30}},
		probe:   SignatureProbeV1{Blank: true},
		fstab:   []byte("# /etc/fstab\nUUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee / ext4 defaults 0 1\n"),
	}
}

func (host *fakeVolumeHost) ListBlockDevices(context.Context) ([]BlockDeviceV1, error) {
	result := make([]BlockDeviceV1, len(host.devices))
	copy(result, host.devices)
	for index := range result {
		result[index].MountPoints = append([]string(nil), host.devices[index].MountPoints...)
	}
	return result, nil
}

func (host *fakeVolumeHost) ProbeSignatures(context.Context, string) (SignatureProbeV1, error) {
	return host.probe, nil
}

func (host *fakeVolumeHost) MakeExt4(context.Context, string) error {
	host.mkfsCalls++
	host.probe = SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: "ext4", UUID: testVolumeUUID}}}
	return nil
}

func (*fakeVolumeHost) EnsureMountPath(context.Context, string) error { return nil }

func (host *fakeVolumeHost) FindMount(context.Context, string) (MountObservationV1, error) {
	return host.mount, nil
}

func (host *fakeVolumeHost) MountExt4(_ context.Context, device, target string, readOnly bool) error {
	host.mountCalls++
	host.mountModes = append(host.mountModes, readOnly)
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	host.mount = MountObservationV1{
		Found: true, DevicePath: device, TargetPath: target, FileSystem: "ext4", UUID: testVolumeUUID, Options: []string{mode},
	}
	for index := range host.devices {
		if host.devices[index].Path == device {
			host.devices[index].MountPoints = []string{target}
		}
	}
	return nil
}

func (host *fakeVolumeHost) ReadFSTab(context.Context) ([]byte, error) {
	return bytes.Clone(host.fstab), nil
}

func (host *fakeVolumeHost) ReplaceFSTab(_ context.Context, expected, replacement []byte) error {
	if !bytes.Equal(host.fstab, expected) {
		return ErrMaterialize
	}
	host.fstab = bytes.Clone(replacement)
	host.fstabWrites++
	return nil
}
