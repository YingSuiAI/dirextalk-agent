package workeramictl

import (
	"context"
	"flag"
	"io"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
)

const usage = "usage: dirextalk-worker-ami <build|verify|destroy> [options]\n"

// Run executes one closed Worker AMI release operation. It never writes AWS
// provider errors or request contents; all externally visible failures are
// fixed, de-secreted categories.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if stdout == nil {
		stdout = io.Discard
	}
	_ = stdout // successful commands persist output or remain silent by design.
	if stderr == nil {
		stderr = io.Discard
	}
	if ctx == nil || !dependencies.valid() || len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "build":
		return runBuild(ctx, args[1:], stderr, dependencies)
	case "verify":
		return runVerify(ctx, args[1:], stderr, dependencies)
	case "destroy":
		return runDestroy(ctx, args[1:], stderr, dependencies)
	default:
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
}

func runBuild(ctx context.Context, args []string, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "strict de-secreted build request JSON")
	outputPath := flags.String("output", "", "new publication manifest JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validLocalPath(*requestPath) || !validLocalPath(*outputPath) {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	prepared, err := parseBuildRequest(*requestPath)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid build request\n")
		return 1
	}
	existing, hasFinal, err := prepareBuildFiles(*outputPath, prepared)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: build intent conflicts with existing state\n")
		return 1
	}
	config, err := loadAndConfirmIdentity(ctx, dependencies, prepared.request.AccountID, prepared.request.Region)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: AWS identity confirmation failed\n")
		return 1
	}
	service, err := dependencies.NewService(config, prepared.adapterConfig)
	if err != nil || service == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI build failed\n")
		return 1
	}
	attestor, err := dependencies.NewAttestor(config)
	if err != nil || attestor == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI build failed\n")
		return 1
	}
	if hasFinal {
		if verifyPublication(ctx, existing, service, attestor) != nil {
			_, _ = io.WriteString(stderr, "worker-ami: existing publication verification failed\n")
			return 1
		}
		if removeBuildIntent(*outputPath) != nil {
			_, _ = io.WriteString(stderr, "worker-ami: publication verified but intent cleanup failed\n")
			return 1
		}
		return 0
	}
	absenceVerifier, err := dependencies.NewAbsenceVerifier(config)
	if err != nil || absenceVerifier == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI build failed\n")
		return 1
	}

	manifest, err := service.Build(ctx, prepared.request)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI build failed\n")
		return 1
	}
	attestCtx, attestCancel := context.WithTimeout(ctx, 5*time.Minute)
	publication, err := attestManifest(attestCtx, manifest, attestor)
	attestCancel()
	if err != nil {
		if cleanupBuiltAMI(ctx, service, absenceVerifier, manifest) != nil {
			_, _ = io.WriteString(stderr, "worker-ami: build failed and cleanup is unconfirmed\n")
		} else {
			_, _ = io.WriteString(stderr, "worker-ami: Worker AMI attestation failed\n")
		}
		return 1
	}
	if writeErr := writeFinalPublication(*outputPath, publication); writeErr != nil {
		// Another identical recovery process may have persisted the exact final
		// manifest first. Verify it rather than deleting the shared AMI.
		persisted, readErr := readPublicationManifest(*outputPath)
		if readErr == nil && publicationMatchesPrepared(persisted, prepared) && verifyPublication(ctx, persisted, service, attestor) == nil {
			if removeBuildIntent(*outputPath) == nil {
				return 0
			}
			_, _ = io.WriteString(stderr, "worker-ami: publication verified but intent cleanup failed\n")
			return 1
		}
		if cleanupBuiltAMI(ctx, service, absenceVerifier, manifest) != nil {
			_, _ = io.WriteString(stderr, "worker-ami: output failed and cleanup is unconfirmed\n")
		} else {
			_, _ = io.WriteString(stderr, "worker-ami: cannot persist publication manifest\n")
		}
		return 1
	}
	if removeBuildIntent(*outputPath) != nil {
		_, _ = io.WriteString(stderr, "worker-ami: publication persisted but intent cleanup failed\n")
		return 1
	}
	return 0
}

func runVerify(ctx context.Context, args []string, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "publication manifest JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validLocalPath(*manifestPath) {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	publication, err := readPublicationManifest(*manifestPath)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid publication manifest\n")
		return 1
	}
	config, err := loadAndConfirmIdentity(ctx, dependencies, publication.ImageManifest.AccountID, publication.ImageManifest.Region)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: AWS identity confirmation failed\n")
		return 1
	}
	service, err := dependencies.NewService(config, awsadapter.Config{Region: publication.ImageManifest.Region, AccountID: publication.ImageManifest.AccountID})
	if err != nil || service == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI verification failed\n")
		return 1
	}
	attestor, err := dependencies.NewAttestor(config)
	if err != nil || attestor == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI verification failed\n")
		return 1
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := service.Verify(verifyCtx, publication.ImageManifest); err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI verification failed\n")
		return 1
	}
	observed, err := attestManifest(verifyCtx, publication.ImageManifest, attestor)
	if err != nil || observed.ImageDigest != publication.ImageDigest {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI verification failed\n")
		return 1
	}
	return 0
}

func runDestroy(ctx context.Context, args []string, stderr io.Writer, dependencies Dependencies) int {
	flags := flag.NewFlagSet("destroy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "strict destroy confirmation JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validLocalPath(*requestPath) {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	_, publication, err := parseDestroyRequest(*requestPath)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: invalid destruction confirmation\n")
		return 1
	}
	config, err := loadAndConfirmIdentity(ctx, dependencies, publication.ImageManifest.AccountID, publication.ImageManifest.Region)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker-ami: AWS identity confirmation failed\n")
		return 1
	}
	service, err := dependencies.NewService(config, awsadapter.Config{Region: publication.ImageManifest.Region, AccountID: publication.ImageManifest.AccountID})
	if err != nil || service == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI destruction failed\n")
		return 1
	}
	absenceVerifier, err := dependencies.NewAbsenceVerifier(config)
	if err != nil || absenceVerifier == nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI destruction failed\n")
		return 1
	}
	destroyCtx, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	if err := service.Destroy(destroyCtx, publication.ImageManifest); err != nil || absenceVerifier.VerifyAbsent(destroyCtx, publication.ImageManifest) != nil {
		_, _ = io.WriteString(stderr, "worker-ami: Worker AMI destruction or absence read-back failed\n")
		return 1
	}
	return 0
}

func attestManifest(ctx context.Context, manifest workerami.ImageManifestV1, attestor AMIAttestor) (PublicationManifestV1, error) {
	request, err := awsprovider.WorkerAMIAttestationRequestFromManifest(manifest)
	if err != nil {
		return PublicationManifestV1{}, errCloudOperation
	}
	evidence, err := attestor.AttestWorkerAMI(ctx, request)
	if err != nil {
		return PublicationManifestV1{}, errCloudOperation
	}
	publication, err := newPublicationManifest(manifest, evidence)
	if err != nil {
		return PublicationManifestV1{}, errCloudOperation
	}
	return publication, nil
}

func prepareBuildFiles(outputPath string, prepared preparedBuild) (PublicationManifestV1, bool, error) {
	finalExists, err := regularFileExists(outputPath)
	if err != nil {
		return PublicationManifestV1{}, false, errOutput
	}
	if !finalExists {
		if err := ensureBuildIntent(outputPath, prepared.intent); err != nil {
			return PublicationManifestV1{}, false, err
		}
		return PublicationManifestV1{}, false, nil
	}
	publication, err := readPublicationManifest(outputPath)
	if err != nil || !publicationMatchesPrepared(publication, prepared) {
		return PublicationManifestV1{}, false, errInvalidInput
	}
	intentExists, err := regularFileExists(buildIntentPath(outputPath))
	if err != nil {
		return PublicationManifestV1{}, false, errOutput
	}
	if intentExists {
		intent, readErr := readBuildIntent(buildIntentPath(outputPath))
		if readErr != nil || intent != prepared.intent {
			return PublicationManifestV1{}, false, errInvalidInput
		}
	}
	return publication, true, nil
}

func verifyPublication(ctx context.Context, publication PublicationManifestV1, service AMIService, attestor AMIAttestor) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if service.Verify(verifyCtx, publication.ImageManifest) != nil {
		return errCloudOperation
	}
	observed, err := attestManifest(verifyCtx, publication.ImageManifest, attestor)
	if err != nil || observed.ImageDigest != publication.ImageDigest {
		return errCloudOperation
	}
	return nil
}

func cleanupBuiltAMI(ctx context.Context, service AMIService, verifier AMIAbsenceVerifier, manifest workerami.ImageManifestV1) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Minute)
	defer cancel()
	if service.Destroy(cleanupCtx, manifest) != nil || verifier.VerifyAbsent(cleanupCtx, manifest) != nil {
		return errCloudOperation
	}
	return nil
}
