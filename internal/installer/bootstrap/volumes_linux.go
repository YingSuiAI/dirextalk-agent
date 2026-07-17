//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	lsblkExecutable    = "/usr/bin/lsblk"
	blkidExecutable    = "/usr/sbin/blkid"
	findmntExecutable  = "/usr/bin/findmnt"
	mkfsExt4Executable = "/usr/sbin/mkfs.ext4"
	mountExecutable    = "/usr/bin/mount"
	fstabPath          = "/etc/fstab"
	maxHostOutput      = 1 << 20
)

type linuxVolumeHost struct{}

func NewLinuxVolumeMaterializer() VolumeMaterializer {
	materializer, err := NewVolumeMaterializer(linuxVolumeHost{})
	if err != nil {
		return unavailableVolumes{}
	}
	return materializer
}

func NewLinuxVolumeStateReader() VolumeStateReader {
	reader, err := NewVolumeStateReader(linuxVolumeHost{})
	if err != nil {
		return unavailableVolumeStateReader{}
	}
	return reader
}

type lsblkDocument struct {
	Devices []struct {
		Path        string      `json:"path"`
		Parent      string      `json:"pkname"`
		Type        string      `json:"type"`
		Size        json.Number `json:"size"`
		Serial      string      `json:"serial"`
		MountPoints []*string   `json:"mountpoints"`
	} `json:"blockdevices"`
}

func (linuxVolumeHost) ListBlockDevices(ctx context.Context) ([]BlockDeviceV1, error) {
	output, err := fixedCommandOutput(ctx, lsblkExecutable,
		"--json", "--bytes", "--paths", "--list", "--output", "PATH,PKNAME,TYPE,SIZE,SERIAL,MOUNTPOINTS")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var document lsblkDocument
	if decoder.Decode(&document) != nil || len(document.Devices) == 0 || len(document.Devices) > 256 {
		return nil, ErrMaterialize
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrMaterialize
	}
	result := make([]BlockDeviceV1, 0, len(document.Devices))
	seen := make(map[string]struct{}, len(document.Devices))
	for _, value := range document.Devices {
		size, parseErr := strconv.ParseUint(value.Size.String(), 10, 64)
		if parseErr != nil || size == 0 || !validDevicePath(value.Path) || (value.Parent != "" && !validDevicePath(normalizeParentPath(value.Parent))) {
			return nil, ErrMaterialize
		}
		if _, duplicate := seen[value.Path]; duplicate {
			return nil, ErrMaterialize
		}
		seen[value.Path] = struct{}{}
		mounts := make([]string, 0, len(value.MountPoints))
		for _, mount := range value.MountPoints {
			if mount != nil && *mount != "" {
				mounts = append(mounts, *mount)
			}
		}
		result = append(result, BlockDeviceV1{
			Path: value.Path, ParentPath: normalizeParentPath(value.Parent), Type: value.Type,
			Serial: value.Serial, SizeBytes: size, MountPoints: mounts,
		})
	}
	return result, nil
}

func (linuxVolumeHost) ProbeSignatures(ctx context.Context, device string) (SignatureProbeV1, error) {
	if !nitroDevicePattern.MatchString(device) {
		return SignatureProbeV1{}, ErrMaterialize
	}
	output, exitCode, err := fixedCommandOutputWithExit(ctx, blkidExecutable, "-p", "-o", "export", device)
	if err != nil {
		return SignatureProbeV1{}, err
	}
	if exitCode == 2 && len(bytes.TrimSpace(output)) == 0 {
		return SignatureProbeV1{Blank: true}, nil
	}
	if exitCode != 0 {
		return SignatureProbeV1{}, ErrMaterialize
	}
	values := make(map[string]string)
	other := false
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || key == "" || value == "" {
			return SignatureProbeV1{}, ErrMaterialize
		}
		if _, duplicate := values[key]; duplicate {
			return SignatureProbeV1{}, ErrMaterialize
		}
		values[key] = value
		if key == "PTTYPE" || key == "PTUUID" {
			other = true
		}
	}
	filesystemType, hasType := values["TYPE"]
	uuid, hasUUID := values["UUID"]
	if !hasType || !hasUUID {
		return SignatureProbeV1{HasOther: true}, nil
	}
	return SignatureProbeV1{FileSystems: []FileSystemSignatureV1{{Type: filesystemType, UUID: uuid}}, HasOther: other}, nil
}

func (linuxVolumeHost) MakeExt4(ctx context.Context, device string) error {
	if !nitroDevicePattern.MatchString(device) {
		return ErrMaterialize
	}
	_, exitCode, err := fixedCommandOutputWithExit(ctx, mkfsExt4Executable, "-q", "-m", "0", "-U", "random", device)
	if err != nil || exitCode != 0 {
		return ErrMaterialize
	}
	return nil
}

func (linuxVolumeHost) EnsureMountPath(ctx context.Context, target string) error {
	if ctx == nil || !mountPathPattern.MatchString(target) || reservedVolumeMount(target) || filepath.Clean(target) != target || ctx.Err() != nil {
		return ErrMaterialize
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.FromSlash(target), string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return ErrMaterialize
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if os.Mkdir(current, 0o755) != nil {
				return ErrMaterialize
			}
			info, err = os.Lstat(current)
		}
		stat, ok := infoSyscall(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrMaterialize
		}
	}
	return nil
}

type findmntDocument struct {
	Filesystems []struct {
		Source  string `json:"source"`
		Target  string `json:"target"`
		FSType  string `json:"fstype"`
		Options string `json:"options"`
		UUID    string `json:"uuid"`
	} `json:"filesystems"`
}

func (linuxVolumeHost) FindMount(ctx context.Context, target string) (MountObservationV1, error) {
	if !mountPathPattern.MatchString(target) || reservedVolumeMount(target) {
		return MountObservationV1{}, ErrMaterialize
	}
	output, exitCode, err := fixedCommandOutputWithExit(ctx, findmntExecutable,
		"--json", "--mountpoint", target, "--output", "SOURCE,TARGET,FSTYPE,OPTIONS,UUID")
	if err != nil {
		return MountObservationV1{}, err
	}
	if exitCode == 1 && len(bytes.TrimSpace(output)) == 0 {
		return MountObservationV1{}, nil
	}
	if exitCode != 0 {
		return MountObservationV1{}, ErrMaterialize
	}
	var document findmntDocument
	decoder := json.NewDecoder(bytes.NewReader(output))
	if decoder.Decode(&document) != nil || len(document.Filesystems) != 1 {
		return MountObservationV1{}, ErrMaterialize
	}
	value := document.Filesystems[0]
	return MountObservationV1{
		Found: true, DevicePath: value.Source, TargetPath: value.Target, FileSystem: value.FSType,
		UUID: value.UUID, Options: strings.Split(value.Options, ","),
	}, nil
}

func (linuxVolumeHost) MountExt4(ctx context.Context, device, target string, readOnly bool) error {
	if !nitroDevicePattern.MatchString(device) || !mountPathPattern.MatchString(target) || reservedVolumeMount(target) {
		return ErrMaterialize
	}
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	_, exitCode, err := fixedCommandOutputWithExit(ctx, mountExecutable, "-t", "ext4", "-o", mode, device, target)
	if err != nil || exitCode != 0 {
		return ErrMaterialize
	}
	return nil
}

func (linuxVolumeHost) ReadFSTab(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrMaterialize
	}
	info, err := os.Lstat(fstabPath)
	stat, ok := infoSyscall(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 ||
		info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > maxHostOutput {
		return nil, ErrMaterialize
	}
	content, err := os.ReadFile(fstabPath)
	if err != nil || len(content) > maxHostOutput {
		return nil, ErrMaterialize
	}
	return content, nil
}

func (host linuxVolumeHost) ReplaceFSTab(ctx context.Context, expected, replacement []byte) error {
	if ctx == nil || len(replacement) == 0 || len(replacement) > maxHostOutput || ctx.Err() != nil {
		return ErrMaterialize
	}
	current, err := host.ReadFSTab(ctx)
	if err != nil || !bytes.Equal(current, expected) {
		return ErrMaterialize
	}
	temporary, err := os.CreateTemp(filepath.Dir(fstabPath), ".dirextalk-fstab.tmp-")
	if err != nil {
		return ErrMaterialize
	}
	name := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(name)
		}
	}()
	if temporary.Chmod(0o644) != nil {
		return ErrMaterialize
	}
	if _, err := temporary.Write(replacement); err != nil || ctx.Err() != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return ErrMaterialize
	}
	info, err := os.Lstat(name)
	stat, ok := infoSyscall(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0o644 || info.Size() != int64(len(replacement)) {
		return ErrMaterialize
	}
	if os.Rename(name, fstabPath) != nil {
		return ErrMaterialize
	}
	renamed = true
	directory, err := os.Open(filepath.Dir(fstabPath))
	if err != nil {
		return ErrMaterialize
	}
	if syncErr, closeErr := directory.Sync(), directory.Close(); syncErr != nil || closeErr != nil {
		return ErrMaterialize
	}
	readBack, err := host.ReadFSTab(ctx)
	if err != nil || !bytes.Equal(readBack, replacement) {
		return ErrMaterialize
	}
	return nil
}

func fixedCommandOutput(ctx context.Context, executable string, args ...string) ([]byte, error) {
	output, exitCode, err := fixedCommandOutputWithExit(ctx, executable, args...)
	if err != nil || exitCode != 0 {
		return nil, ErrMaterialize
	}
	return output, nil
}

func fixedCommandOutputWithExit(ctx context.Context, executable string, args ...string) ([]byte, int, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, -1, ErrMaterialize
	}
	command := exec.CommandContext(ctx, executable, args...)
	output, err := command.Output()
	if len(output) > maxHostOutput {
		return nil, -1, ErrMaterialize
	}
	if err == nil {
		return output, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), nil
	}
	return nil, -1, ErrMaterialize
}

func validDevicePath(value string) bool {
	return strings.HasPrefix(value, "/dev/") && mountPathPattern.MatchString(value) && filepath.Clean(value) == value
}

func normalizeParentPath(value string) string {
	if value == "" || strings.HasPrefix(value, "/dev/") {
		return value
	}
	return "/dev/" + value
}
