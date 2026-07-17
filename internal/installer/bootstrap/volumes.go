package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	nitroDevicePattern      = regexp.MustCompile(`^/dev/nvme[0-9]+n[0-9]+$`)
	attachmentDevicePattern = regexp.MustCompile(`^/dev/sd[f-p]$`)
	filesystemUUIDPattern   = regexp.MustCompile(`^[0-9A-Fa-f][0-9A-Fa-f-]{3,63}$`)
	mountPathPattern        = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

type BlockDeviceV1 struct {
	Path        string
	ParentPath  string
	Type        string
	Serial      string
	SizeBytes   uint64
	MountPoints []string
}

type FileSystemSignatureV1 struct {
	Type string
	UUID string
}

type SignatureProbeV1 struct {
	Blank       bool
	FileSystems []FileSystemSignatureV1
	HasOther    bool
}

type MountObservationV1 struct {
	Found      bool
	DevicePath string
	TargetPath string
	FileSystem string
	UUID       string
	Options    []string
}

type InstalledVolumeObservationV1 struct {
	ResolvedDevicePath string
	SizeBytes          uint64
	FileSystem         string
	FileSystemUUID     string
	MountPath          string
	ReadOnly           bool
}

type VolumeStateReader interface {
	Observe(context.Context, string, string) (InstalledVolumeObservationV1, error)
}

type approvedVolumeStateReader struct{ host VolumeHost }

type unavailableVolumeStateReader struct{}

func (unavailableVolumeStateReader) Observe(context.Context, string, string) (InstalledVolumeObservationV1, error) {
	return InstalledVolumeObservationV1{}, ErrMaterialize
}

func NewVolumeStateReader(host VolumeHost) (VolumeStateReader, error) {
	if host == nil {
		return nil, ErrInvalidInput
	}
	return &approvedVolumeStateReader{host: host}, nil
}

// Observe resolves the stable EBS VolumeID again and verifies the active
// whole-device ext4 mount. Nitro device paths are intentionally not treated
// as stable across boots.
func (reader *approvedVolumeStateReader) Observe(ctx context.Context, volumeID, mountPath string) (InstalledVolumeObservationV1, error) {
	if reader == nil || reader.host == nil || ctx == nil || ctx.Err() != nil ||
		!volumeIDPattern.MatchString(volumeID) || !mountPathPattern.MatchString(mountPath) || reservedVolumeMount(mountPath) {
		return InstalledVolumeObservationV1{}, ErrMaterialize
	}
	devices, err := reader.host.ListBlockDevices(ctx)
	if err != nil {
		return InstalledVolumeObservationV1{}, ErrMaterialize
	}
	wanted := normalizeVolumeSerial(volumeID)
	matches := make([]BlockDeviceV1, 0, 1)
	for _, device := range devices {
		if device.Type == "disk" && nitroDevicePattern.MatchString(device.Path) && normalizeVolumeSerial(device.Serial) == wanted {
			matches = append(matches, device)
		}
	}
	if len(matches) != 1 {
		return InstalledVolumeObservationV1{}, ErrMaterialize
	}
	device := matches[0]
	for _, candidate := range devices {
		if descendantOf(candidate.Path, device.Path, devices) {
			return InstalledVolumeObservationV1{}, ErrMaterialize
		}
	}
	probe, err := reader.host.ProbeSignatures(ctx, device.Path)
	if err != nil || probe.Blank || probe.HasOther || len(probe.FileSystems) != 1 ||
		probe.FileSystems[0].Type != "ext4" || !filesystemUUIDPattern.MatchString(probe.FileSystems[0].UUID) {
		return InstalledVolumeObservationV1{}, ErrMaterialize
	}
	uuid := strings.ToLower(probe.FileSystems[0].UUID)
	mount, err := reader.host.FindMount(ctx, mountPath)
	if err != nil || !mount.Found || mount.DevicePath != device.Path || mount.TargetPath != mountPath ||
		mount.FileSystem != "ext4" || strings.ToLower(mount.UUID) != uuid {
		return InstalledVolumeObservationV1{}, ErrMaterialize
	}
	return InstalledVolumeObservationV1{
		ResolvedDevicePath: device.Path, SizeBytes: device.SizeBytes, FileSystem: "ext4", FileSystemUUID: uuid,
		MountPath: mountPath, ReadOnly: slices.Contains(mount.Options, "ro"),
	}, nil
}

// VolumeHost is deliberately typed around fixed filesystem operations. The
// Linux implementation invokes only fixed executables with separately
// validated argv and performs the fstab replacement itself; no caller can
// submit a shell program or command string.
type VolumeHost interface {
	ListBlockDevices(context.Context) ([]BlockDeviceV1, error)
	ProbeSignatures(context.Context, string) (SignatureProbeV1, error)
	MakeExt4(context.Context, string) error
	EnsureMountPath(context.Context, string) error
	FindMount(context.Context, string) (MountObservationV1, error)
	MountExt4(context.Context, string, string, bool) error
	ReadFSTab(context.Context) ([]byte, error)
	ReplaceFSTab(context.Context, []byte, []byte) error
}

type approvedVolumeMaterializer struct{ host VolumeHost }

func NewVolumeMaterializer(host VolumeHost) (VolumeMaterializer, error) {
	if host == nil {
		return nil, ErrInvalidInput
	}
	return &approvedVolumeMaterializer{host: host}, nil
}

func (materializer *approvedVolumeMaterializer) Prepare(ctx context.Context, volumes []VolumeMountV1) ([]InstalledVolumeEvidenceV1, error) {
	if materializer == nil || materializer.host == nil || ctx == nil {
		return nil, ErrMaterialize
	}
	if len(volumes) == 0 {
		return []InstalledVolumeEvidenceV1{}, nil
	}
	if len(volumes) > 11 || ctx.Err() != nil {
		return nil, ErrMaterialize
	}
	installed := make([]InstalledVolumeEvidenceV1, 0, len(volumes))
	seenIDs := make(map[string]struct{}, len(volumes))
	seenDevices := make(map[string]struct{}, len(volumes))
	seenMounts := make(map[string]struct{}, len(volumes))
	selectedPaths := make(map[string]struct{}, len(volumes))
	for _, volume := range volumes {
		if !validVolumeMount(volume) {
			return nil, ErrMaterialize
		}
		if _, duplicate := seenIDs[volume.Source.VolumeID]; duplicate {
			return nil, ErrMaterialize
		}
		if _, duplicate := seenDevices[volume.Approved.DeviceName]; duplicate {
			return nil, ErrMaterialize
		}
		if _, duplicate := seenMounts[volume.Approved.MountPath]; duplicate {
			return nil, ErrMaterialize
		}
		seenIDs[volume.Source.VolumeID] = struct{}{}
		seenDevices[volume.Approved.DeviceName] = struct{}{}
		seenMounts[volume.Approved.MountPath] = struct{}{}
		devices, err := materializer.host.ListBlockDevices(ctx)
		if err != nil {
			return nil, ErrMaterialize
		}
		device, err := resolveNitroVolume(devices, volume)
		if err != nil {
			return nil, err
		}
		if _, duplicate := selectedPaths[device.Path]; duplicate {
			return nil, ErrMaterialize
		}
		selectedPaths[device.Path] = struct{}{}
		evidence, err := materializer.prepareOne(ctx, volume, device)
		if err != nil {
			return nil, err
		}
		installed = append(installed, evidence)
	}
	return installed, nil
}

func (materializer *approvedVolumeMaterializer) prepareOne(ctx context.Context, volume VolumeMountV1, device BlockDeviceV1) (InstalledVolumeEvidenceV1, error) {
	probe, err := materializer.host.ProbeSignatures(ctx, device.Path)
	if err != nil {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	uuid := ""
	if probe.Blank && len(probe.FileSystems) == 0 && !probe.HasOther {
		devices, listErr := materializer.host.ListBlockDevices(ctx)
		confirmed, resolveErr := resolveNitroVolume(devices, volume)
		if listErr != nil || resolveErr != nil || confirmed.Path != device.Path {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		if err := materializer.host.MakeExt4(ctx, device.Path); err != nil {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		probe, err = materializer.host.ProbeSignatures(ctx, device.Path)
		if err != nil {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
	}
	if probe.Blank || len(probe.FileSystems) != 1 || probe.HasOther {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	signature := probe.FileSystems[0]
	if signature.Type != "ext4" || !filesystemUUIDPattern.MatchString(signature.UUID) {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	uuid = strings.ToLower(signature.UUID)
	observation, err := materializer.host.FindMount(ctx, volume.Approved.MountPath)
	if err != nil {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	if observation.Found {
		if !mountMatches(observation, device.Path, volume.Approved.MountPath, uuid, volume.Approved.ReadOnly) {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
	} else {
		if err := materializer.host.EnsureMountPath(ctx, volume.Approved.MountPath); err != nil {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		if err := materializer.host.MountExt4(ctx, device.Path, volume.Approved.MountPath, volume.Approved.ReadOnly); err != nil {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		observation, err = materializer.host.FindMount(ctx, volume.Approved.MountPath)
		if err != nil || !mountMatches(observation, device.Path, volume.Approved.MountPath, uuid, volume.Approved.ReadOnly) {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
	}
	current, err := materializer.host.ReadFSTab(ctx)
	if err != nil {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	if !volume.Approved.Persistent {
		if fstabConflicts(current, uuid, volume.Approved.MountPath) {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		return materializer.observeEvidence(ctx, volume)
	}
	next, err := withPersistentVolume(current, uuid, volume)
	if err != nil {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	if !bytes.Equal(current, next) {
		if err := materializer.host.ReplaceFSTab(ctx, current, next); err != nil {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
		readBack, err := materializer.host.ReadFSTab(ctx)
		if err != nil || !bytes.Equal(readBack, next) {
			return InstalledVolumeEvidenceV1{}, ErrMaterialize
		}
	}
	return materializer.observeEvidence(ctx, volume)
}

func (materializer *approvedVolumeMaterializer) observeEvidence(ctx context.Context, volume VolumeMountV1) (InstalledVolumeEvidenceV1, error) {
	reader := &approvedVolumeStateReader{host: materializer.host}
	observed, err := reader.Observe(ctx, volume.Source.VolumeID, volume.Approved.MountPath)
	if err != nil || observed.SizeBytes != uint64(volume.Approved.SizeGiB)<<30 || observed.ReadOnly != volume.Approved.ReadOnly {
		return InstalledVolumeEvidenceV1{}, ErrMaterialize
	}
	return InstalledVolumeEvidenceV1{
		Name: volume.Approved.Name, ResourceID: volume.Source.ResourceID, VolumeID: volume.Source.VolumeID,
		AttachmentDevice: volume.Approved.DeviceName, ResolvedDevicePath: observed.ResolvedDevicePath, SizeBytes: observed.SizeBytes,
		FileSystem: observed.FileSystem, FileSystemUUID: observed.FileSystemUUID, MountPath: observed.MountPath, ReadOnly: observed.ReadOnly,
	}, nil
}

func validVolumeMount(value VolumeMountV1) bool {
	approved := value.Approved
	return value.Source.SchemaVersion == VolumeSourceSchemaV1 && value.Source.Name == approved.Name && canonicalUUID(value.Source.ResourceID) &&
		volumeIDPattern.MatchString(value.Source.VolumeID) && value.Source.DeviceName == approved.DeviceName &&
		approved.SizeGiB > 0 && attachmentDevicePattern.MatchString(approved.DeviceName) &&
		mountPathPattern.MatchString(approved.MountPath) && path.Clean(approved.MountPath) == approved.MountPath && !reservedVolumeMount(approved.MountPath) &&
		(approved.Disposition == "delete_with_deployment" || approved.Disposition == "retain_with_managed_service")
}

func reservedVolumeMount(value string) bool {
	for _, root := range []string{"/", "/boot", "/dev", "/efi", "/etc", "/home", "/proc", "/run", "/sys", "/tmp", "/usr"} {
		if value == root || strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}

func resolveNitroVolume(devices []BlockDeviceV1, volume VolumeMountV1) (BlockDeviceV1, error) {
	wantedSerial := normalizeVolumeSerial(volume.Source.VolumeID)
	matches := make([]BlockDeviceV1, 0, 1)
	for _, device := range devices {
		if device.Type == "disk" && nitroDevicePattern.MatchString(device.Path) && normalizeVolumeSerial(device.Serial) == wantedSerial {
			matches = append(matches, device)
		}
	}
	if len(matches) != 1 {
		return BlockDeviceV1{}, ErrMaterialize
	}
	candidate := matches[0]
	minimumBytes := uint64(volume.Approved.SizeGiB) << 30
	// A larger volume is not harmless here: it changes the approved storage
	// amount and therefore the cost/resource scope that the user signed. Any
	// resize must go through a new quote, plan, and signed bootstrap manifest.
	if candidate.SizeBytes != minimumBytes {
		return BlockDeviceV1{}, ErrMaterialize
	}
	for _, device := range devices {
		if device.Path == candidate.Path {
			for _, mount := range device.MountPoints {
				if mount != "" && mount != volume.Approved.MountPath {
					return BlockDeviceV1{}, ErrMaterialize
				}
			}
			continue
		}
		if descendantOf(device.Path, candidate.Path, devices) {
			// Approved EBS filesystems are placed directly on the whole device.
			// A partition table, root filesystem child, or other stacked device is
			// never reformatted or mounted by this bootstrap.
			return BlockDeviceV1{}, ErrMaterialize
		}
	}
	return candidate, nil
}

func descendantOf(devicePath, ancestorPath string, devices []BlockDeviceV1) bool {
	parents := make(map[string]string, len(devices))
	for _, device := range devices {
		parents[device.Path] = device.ParentPath
	}
	seen := make(map[string]struct{}, len(devices))
	for current := devicePath; current != ""; current = parents[current] {
		if current == ancestorPath && current != devicePath {
			return true
		}
		if _, loop := seen[current]; loop {
			return false
		}
		seen[current] = struct{}{}
	}
	return false
}

func normalizeVolumeSerial(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "")
}

func mountMatches(value MountObservationV1, device, target, uuid string, readOnly bool) bool {
	if !value.Found || value.DevicePath != device || value.TargetPath != target || value.FileSystem != "ext4" ||
		strings.ToLower(value.UUID) != uuid {
		return false
	}
	ro := slices.Contains(value.Options, "ro")
	rw := slices.Contains(value.Options, "rw")
	if readOnly {
		return ro && !rw
	}
	return rw && !ro
}

func withPersistentVolume(current []byte, uuid string, volume VolumeMountV1) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(current), "\n"), "\n")
	kept := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(kept) != 0 && kept[len(kept)-1] != "" {
				kept = append(kept, "")
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "UUID="+uuid || fields[1] == volume.Approved.MountPath) {
			if len(fields) < 4 || fields[0] != "UUID="+uuid || fields[1] != volume.Approved.MountPath || fields[2] != "ext4" {
				return nil, ErrMaterialize
			}
			continue
		}
		kept = append(kept, line)
	}
	for len(kept) != 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	options := "defaults,nofail"
	if volume.Approved.ReadOnly {
		options += ",ro"
	}
	kept = append(kept, fmt.Sprintf("UUID=%s %s ext4 %s 0 2 # dirextalk-volume=%s", uuid, volume.Approved.MountPath, options, volume.Source.VolumeID))
	return []byte(strings.Join(kept, "\n") + "\n"), nil
}

func fstabConflicts(current []byte, uuid, mountPath string) bool {
	for _, line := range strings.Split(string(current), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "UUID="+uuid || fields[1] == mountPath) {
			return true
		}
	}
	return false
}
