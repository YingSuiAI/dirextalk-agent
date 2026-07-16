package bootstrap

import (
	"context"
	"errors"
	"io"
	"io/fs"
)

type MetadataSource interface {
	Read(context.Context) ([]byte, InstanceIdentityV1, error)
}

type TrustFileSpec struct {
	Path string
	Mode fs.FileMode
	UID  int
	GID  int
}

type TrustMaterializer interface {
	Replace(context.Context, TrustFileSpec, []byte) (bool, error)
}

type ArtifactDownload struct {
	Body io.ReadCloser
}

type ArtifactDownloader interface {
	Open(context.Context, ArtifactSourceV1) (ArtifactDownload, error)
}

type ArtifactFileSpec struct {
	Path      string
	Mode      fs.FileMode
	UID       int
	GID       int
	SHA256    string
	SizeBytes int64
}

type ArtifactMaterializer interface {
	Replace(context.Context, ArtifactFileSpec, io.Reader) (bool, error)
}

// SocketController must leave the socket disabled when either method returns
// an error. Enable implementations therefore compensate a partial enable or
// start before returning failure.
type SocketController interface {
	Disable(context.Context) error
	Enable(context.Context) error
}

type Service struct {
	source     MetadataSource
	trust      TrustMaterializer
	downloader ArtifactDownloader
	artifacts  ArtifactMaterializer
	socket     SocketController
	trustFile  string
}

// NewService preserves the no-artifact constructor for Recipes that omit the
// installer capability. If installer sources are present it deliberately
// fails closed; production bootstrap uses NewArtifactService.
func NewService(source MetadataSource, trust TrustMaterializer, socket SocketController, trustFile string) (*Service, error) {
	return NewArtifactService(source, trust, unavailableArtifacts{}, unavailableArtifacts{}, socket, trustFile)
}

func NewArtifactService(source MetadataSource, trust TrustMaterializer, downloader ArtifactDownloader, artifacts ArtifactMaterializer, socket SocketController, trustFile string) (*Service, error) {
	if source == nil || trust == nil || downloader == nil || artifacts == nil || socket == nil || trustFile != DefaultTrustFile {
		return nil, ErrInvalidInput
	}
	return &Service{source: source, trust: trust, downloader: downloader, artifacts: artifacts, socket: socket, trustFile: trustFile}, nil
}

type unavailableArtifacts struct{}

func (unavailableArtifacts) Open(context.Context, ArtifactSourceV1) (ArtifactDownload, error) {
	return ArtifactDownload{}, ErrArtifactSource
}

func (unavailableArtifacts) Replace(context.Context, ArtifactFileSpec, io.Reader) (bool, error) {
	return false, ErrMaterialize
}

// Run disables the privileged socket before reading any external input. Every
// failure path returns without re-enabling it. A Worker without an installer
// capability exits successfully while leaving the socket disabled; only a
// fully validated and durably replaced trust file can make it reachable.
func (service *Service) Run(ctx context.Context) error {
	if service == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := service.socket.Disable(ctx); err != nil {
		return errors.Join(ErrSocketActivation, err)
	}
	raw, identity, err := service.source.Read(ctx)
	if err != nil {
		clear(raw)
		return ErrInvalidInput
	}
	defer clear(raw)
	userData, trust, err := ParseUserData(raw, identity)
	if err != nil {
		return err
	}
	if trust == nil {
		return nil
	}
	for _, source := range userData.InstallerArtifacts {
		download, openErr := service.downloader.Open(ctx, source)
		if openErr != nil || download.Body == nil {
			if download.Body != nil {
				_ = download.Body.Close()
			}
			return errors.Join(ErrMaterialize, openErr)
		}
		_, replaceErr := service.artifacts.Replace(ctx, ArtifactFileSpec{
			Path: source.TargetPath, Mode: 0o500, UID: 0, GID: 0,
			SHA256: source.SHA256, SizeBytes: source.SizeBytes,
		}, download.Body)
		closeErr := download.Body.Close()
		if replaceErr != nil || closeErr != nil {
			return errors.Join(ErrMaterialize, replaceErr, closeErr)
		}
	}
	encoded, err := EncodeTrustFile(*trust)
	if err != nil {
		return err
	}
	defer clear(encoded)
	_, err = service.trust.Replace(ctx, TrustFileSpec{
		Path: service.trustFile, Mode: 0o400, UID: 0, GID: 0,
	}, encoded)
	if err != nil {
		return errors.Join(ErrMaterialize, err)
	}
	if err := service.socket.Enable(ctx); err != nil {
		return errors.Join(ErrSocketActivation, err)
	}
	return nil
}
