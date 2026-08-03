package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLoadCommonReadsDatabaseURLOnlyFromMountedSecretFile(t *testing.T) {
	path := writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require\n")
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", path)
	t.Setenv("AGENT_DATABASE_URL", "postgres://must-not-be-used")

	common, err := LoadCommon()
	if err != nil {
		t.Fatalf("LoadCommon: %v", err)
	}
	if common.DatabaseURL != "postgres://agent:password@db.example/agent?sslmode=require" {
		t.Fatalf("unexpected database URL source")
	}
}

func TestLoadCommonRejectsLegacyDatabaseURLEnvironmentVariable(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", "")
	t.Setenv("AGENT_DATABASE_URL", "postgres://legacy")

	_, err := LoadCommon()
	if err == nil || !strings.Contains(err.Error(), "AGENT_DATABASE_URL_FILE is required") {
		t.Fatalf("LoadCommon error = %v", err)
	}
}

func TestLoadServerRequiresMountedRuntimeSecretDirectory(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MOUNTED_SECRETS_DIR is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRequiresModelProfileCatalog(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MODEL_PROFILES_FILE is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRequiresMountedAgentMasterKey(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MASTER_KEY_FILE", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MASTER_KEY_FILE is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRequiresRuntimeCatalogAndPublicKeyTogether(t *testing.T) {
	tests := map[string]struct {
		catalog string
		key     string
		policy  string
		valid   bool
	}{
		"disabled": {},
		"catalog only": {
			catalog: "/run/dirextalk/config/runtime-catalog.json",
		},
		"key only": {
			key: "/run/dirextalk/config/runtime-catalog-public-key",
		},
		"policy only": {
			policy: "/run/dirextalk/config/team-policy.json",
		},
		"configured pair": {
			catalog: "/run/dirextalk/config/runtime-catalog.json",
			key:     "/run/dirextalk/config/runtime-catalog-public-key",
			valid:   true,
		},
		"configured policy": {
			catalog: "/run/dirextalk/config/runtime-catalog.json",
			key:     "/run/dirextalk/config/runtime-catalog-public-key",
			policy:  "/run/dirextalk/config/team-policy.json",
			valid:   true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv("AGENT_RUNTIME_CATALOG_FILE", test.catalog)
			t.Setenv("AGENT_RUNTIME_CATALOG_PUBLIC_KEY_FILE", test.key)
			t.Setenv("AGENT_TEAM_POLICY_FILE", test.policy)
			server, err := LoadServer()
			if test.catalog == "" && test.key == "" && test.policy == "" {
				if err != nil || server.RuntimeCatalogFile != "" ||
					server.RuntimeCatalogPublicKeyFile != "" ||
					server.TeamPolicyFile != "" {
					t.Fatalf("disabled runtime catalog = %#v, %v", server, err)
				}
				return
			}
			if !test.valid {
				if err == nil {
					t.Fatalf("unpaired runtime catalog error = %v", err)
				}
				return
			}
			if err != nil || server.RuntimeCatalogFile != test.catalog ||
				server.RuntimeCatalogPublicKeyFile != test.key ||
				server.TeamPolicyFile != test.policy {
				t.Fatalf("runtime catalog config = %#v, %v", server, err)
			}
		})
	}
}

func TestLoadServerKeepsWorkerMarketplaceBehindCompleteTrustConfig(
	t *testing.T,
) {
	registryPath :=
		"/run/dirextalk/config/worker-market-registry.json"
	keyPath :=
		"/run/dirextalk/config/worker-market-public-key"

	t.Run("registry and key must be paired", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"AGENT_WORKER_MARKET_REGISTRY_FILE and AGENT_WORKER_MARKET_PUBLIC_KEY_FILE",
			) {
			t.Fatalf("unpaired Worker Marketplace error=%v", err)
		}
	})

	t.Run("registry requires runtime catalog", func(t *testing.T) {
		setValidServerEnvironment(t)
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		t.Setenv("AGENT_WORKER_MARKET_PUBLIC_KEY_FILE", keyPath)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "signed Runtime Catalog") {
			t.Fatalf("missing Runtime Catalog error=%v", err)
		}
	})

	t.Run("registry requires Team policy", func(t *testing.T) {
		setValidServerEnvironment(t)
		t.Setenv(
			"AGENT_RUNTIME_CATALOG_FILE",
			"/run/dirextalk/config/runtime-catalog.json",
		)
		t.Setenv(
			"AGENT_RUNTIME_CATALOG_PUBLIC_KEY_FILE",
			"/run/dirextalk/config/runtime-catalog-public-key",
		)
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		t.Setenv("AGENT_WORKER_MARKET_PUBLIC_KEY_FILE", keyPath)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "AGENT_TEAM_POLICY_FILE") {
			t.Fatalf("missing Team policy error=%v", err)
		}
	})

	t.Run("organization scope must be canonical", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		t.Setenv("AGENT_WORKER_MARKET_PUBLIC_KEY_FILE", keyPath)
		t.Setenv("AGENT_WORKER_MARKET_ORGANIZATION_ID", "tenant-a")
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "canonical UUID") {
			t.Fatalf("invalid organization scope error=%v", err)
		}
	})

	t.Run("complete configuration", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		organizationID := uuid.NewString()
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		t.Setenv("AGENT_WORKER_MARKET_PUBLIC_KEY_FILE", keyPath)
		t.Setenv(
			"AGENT_WORKER_MARKET_ORGANIZATION_ID",
			organizationID,
		)
		server, err := LoadServer()
		if err != nil ||
			server.WorkerMarketRegistryFile != registryPath ||
			server.WorkerMarketPublicKeyFile != keyPath ||
			server.WorkerMarketOrganizationID != organizationID {
			t.Fatalf(
				"Worker Marketplace config=%#v error=%v",
				server,
				err,
			)
		}
	})

	t.Run("signed Team bundle supplies catalog and policy", func(t *testing.T) {
		setValidServerEnvironment(t)
		setAWSControlEnvironment(t)
		const bundleDirectory = "/run/dirextalk/pi-team-bundle"
		t.Setenv("AGENT_TEAM_BUNDLE_DIR", bundleDirectory)
		t.Setenv(
			"AGENT_MODEL_PROFILES_FILE",
			bundleDirectory+"/model-profiles.json",
		)
		t.Setenv("AGENT_WORKER_MARKET_REGISTRY_FILE", registryPath)
		t.Setenv("AGENT_WORKER_MARKET_PUBLIC_KEY_FILE", keyPath)
		organizationID := uuid.NewString()
		t.Setenv("AGENT_WORKER_MARKET_ORGANIZATION_ID", organizationID)
		server, err := LoadServer()
		if err != nil || server.TeamBundleDir != bundleDirectory ||
			server.WorkerMarketRegistryFile != registryPath ||
			server.WorkerMarketPublicKeyFile != keyPath ||
			server.WorkerMarketOrganizationID != organizationID {
			t.Fatalf(
				"bundled Worker Marketplace config=%#v error=%v",
				server,
				err,
			)
		}
	})
}

func TestLoadServerKeepsTeamPricingBehindCompleteTrustedAWSConfig(
	t *testing.T,
) {
	t.Run("catalogs must be paired", func(t *testing.T) {
		setValidServerEnvironment(t)
		t.Setenv(
			"AGENT_TEAM_MODEL_OFFER_CATALOG_FILE",
			"/run/dirextalk/config/team-model-offers.json",
		)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"AGENT_TEAM_MODEL_OFFER_CATALOG_FILE and AGENT_TEAM_COMPUTE_CATALOG_FILE",
			) {
			t.Fatalf("unpaired Team pricing error=%v", err)
		}
	})

	t.Run("catalogs require policy", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamPricingCatalogEnvironment(t)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "AGENT_TEAM_POLICY_FILE") {
			t.Fatalf("missing Team policy error=%v", err)
		}
	})

	t.Run("catalogs require AWS control", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		setTeamPricingCatalogEnvironment(t)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"AGENT_ENABLE_AWS_CONTROL=true",
			) {
			t.Fatalf("missing AWS control error=%v", err)
		}
	})

	t.Run("catalogs reject staged Worker control", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		setTeamPricingCatalogEnvironment(t)
		setAWSControlEnvironment(t)
		t.Setenv(
			"AGENT_WORKER_CONNECTIVITY_MODE",
			"no_nat_endpoints_v1",
		)
		t.Setenv(
			"AGENT_WORKER_CONTROL_ENDPOINT",
			"grpcs://worker-control.y1.dirextalk.ai:443",
		)
		t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "")
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"complete Worker Control configuration",
			) {
			t.Fatalf("staged Worker control error=%v", err)
		}
	})

	t.Run("complete configuration", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		setTeamPricingCatalogEnvironment(t)
		setAWSControlEnvironment(t)
		server, err := LoadServer()
		if err != nil ||
			server.TeamModelOfferCatalogFile == "" ||
			server.TeamComputeCatalogFile == "" ||
			!server.EnableAWSControl ||
			server.StagedWorkerControl {
			t.Fatalf("Team pricing config=%#v error=%v", server, err)
		}
	})
}

func TestLoadServerEnablesOnlyCompletePiTeamBundle(t *testing.T) {
	const bundleDirectory = "/run/dirextalk/pi-team-bundle"
	setBundle := func(t *testing.T) {
		t.Helper()
		t.Setenv("AGENT_TEAM_BUNDLE_DIR", bundleDirectory)
		t.Setenv(
			"AGENT_MODEL_PROFILES_FILE",
			bundleDirectory+"/model-profiles.json",
		)
	}

	t.Run("complete configuration", func(t *testing.T) {
		setValidServerEnvironment(t)
		setAWSControlEnvironment(t)
		setBundle(t)
		server, err := LoadServer()
		if err != nil ||
			server.TeamBundleDir != bundleDirectory ||
			server.ModelProfilesFile !=
				bundleDirectory+"/model-profiles.json" ||
			!server.EnableAWSControl ||
			server.StagedWorkerControl {
			t.Fatalf("Team bundle config=%#v error=%v", server, err)
		}
	})

	t.Run("requires AWS control", func(t *testing.T) {
		setValidServerEnvironment(t)
		setBundle(t)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"AGENT_ENABLE_AWS_CONTROL=true",
			) {
			t.Fatalf("missing AWS control error=%v", err)
		}
	})

	t.Run("requires bundled model catalog", func(t *testing.T) {
		setValidServerEnvironment(t)
		setAWSControlEnvironment(t)
		t.Setenv("AGENT_TEAM_BUNDLE_DIR", bundleDirectory)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"must select the Team bundle model catalog",
			) {
			t.Fatalf("external model catalog error=%v", err)
		}
	})

	t.Run("rejects loose release files", func(t *testing.T) {
		setValidServerEnvironment(t)
		setAWSControlEnvironment(t)
		setBundle(t)
		t.Setenv(
			"AGENT_WORKER_AMI_PUBLICATION_FILE",
			"/run/dirextalk/config/publication.json",
		)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "loose Team release files") {
			t.Fatalf("loose release file error=%v", err)
		}
	})

	t.Run("rejects noncanonical directory", func(t *testing.T) {
		setValidServerEnvironment(t)
		setAWSControlEnvironment(t)
		t.Setenv(
			"AGENT_TEAM_BUNDLE_DIR",
			"/run/dirextalk/../dirextalk/pi-team-bundle",
		)
		t.Setenv(
			"AGENT_MODEL_PROFILES_FILE",
			"/run/dirextalk/pi-team-bundle/model-profiles.json",
		)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "absolute protected") {
			t.Fatalf("noncanonical bundle directory error=%v", err)
		}
	})
}

func TestLoadServerKeepsGitHubAppConnectionsBehindTeamAWSBoundary(
	t *testing.T,
) {
	t.Run("connections require Team policy", func(t *testing.T) {
		setValidServerEnvironment(t)
		t.Setenv(
			"AGENT_GITHUB_APP_CONNECTIONS_FILE",
			"/run/dirextalk/config/github-app-connections.json",
		)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(err.Error(), "AGENT_TEAM_POLICY_FILE") {
			t.Fatalf("missing Team policy error=%v", err)
		}
	})

	t.Run("connections require AWS control", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		t.Setenv(
			"AGENT_GITHUB_APP_CONNECTIONS_FILE",
			"/run/dirextalk/config/github-app-connections.json",
		)
		if _, err := LoadServer(); err == nil ||
			!strings.Contains(
				err.Error(),
				"AGENT_ENABLE_AWS_CONTROL=true",
			) {
			t.Fatalf("missing AWS control error=%v", err)
		}
	})

	t.Run("complete configuration", func(t *testing.T) {
		setValidServerEnvironment(t)
		setTeamTrustEnvironment(t)
		setAWSControlEnvironment(t)
		path :=
			"/run/dirextalk/config/github-app-connections.json"
		t.Setenv("AGENT_GITHUB_APP_CONNECTIONS_FILE", path)
		server, err := LoadServer()
		if err != nil ||
			server.GitHubAppConnectionsFile != path {
			t.Fatalf("GitHub App config=%#v error=%v", server, err)
		}
	})
}

func TestLoadServerRejectsMutableOrReservedReaperImageTags(t *testing.T) {
	for _, image := range []string{
		"registry.example/reaper:latest@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:v1.0.3@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:v0.1.0@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:alpha",
	} {
		t.Run(image, func(t *testing.T) {
			t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
			t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
			t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
			t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
			t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
			t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
			t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
			t.Setenv("AGENT_MASTER_KEY_FILE", "master-key")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", image)
			if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "immutable digest-pinned") {
				t.Fatalf("image %q error=%v", image, err)
			}
		})
	}
}

func TestLoadServerRequiresCredentialFreeGRPCSWorkerControlEndpointForAWS(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		valid    bool
	}{
		"missing":         {endpoint: ""},
		"non grpcs":       {endpoint: "https://worker-control.internal:9444"},
		"embedded secret": {endpoint: "grpcs://worker:secret@worker-control.internal:9444"},
		"non-443 port":    {endpoint: "grpcs://worker-control.internal:9444"},
		"valid":           {endpoint: "grpcs://worker-control.y1.dirextalk.ai:443", valid: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", test.endpoint)
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

			server, err := LoadServer()
			if !test.valid {
				if err == nil || !strings.Contains(err.Error(), "AGENT_WORKER_CONTROL_ENDPOINT") {
					t.Fatalf("endpoint %q error=%v", test.endpoint, err)
				}
				return
			}
			if err != nil || server.WorkerControlEndpoint != test.endpoint {
				t.Fatalf("LoadServer endpoint=%q error=%v", server.WorkerControlEndpoint, err)
			}
		})
	}
}

func TestLoadServerKeepsAWSControlFailClosedUnlessExplicitlyEnabled(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

	server, err := LoadServer()
	if err != nil || server.EnableAWSControl {
		t.Fatalf("LoadServer() enable_aws=%v error=%v", server.EnableAWSControl, err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	server, err = LoadServer()
	if err != nil || !server.EnableAWSControl {
		t.Fatalf("enabled LoadServer() enable_aws=%v error=%v", server.EnableAWSControl, err)
	}
}

func TestLoadServerKeepsManagedPreparationAWSBehindIndependentExplicitGate(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

	server, err := LoadServer()
	if err != nil || server.EnableManagedPreparationAWS {
		t.Fatalf("default managed preparation gate=%v error=%v", server.EnableManagedPreparationAWS, err)
	}

	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "true")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "requires AGENT_ENABLE_AWS_CONTROL=true") {
		t.Fatalf("managed preparation without AWS control error=%v", err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	server, err = LoadServer()
	if err != nil || !server.EnableManagedPreparationAWS {
		t.Fatalf("explicit managed preparation gate=%v error=%v", server.EnableManagedPreparationAWS, err)
	}
}

func TestLoadServerStagesWorkerControlPrivateLinkWithoutChangingInstanceIdentity(t *testing.T) {
	setValidServerEnvironment(t)
	instanceID := os.Getenv("AGENT_INSTANCE_ID")
	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "false")
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "")

	staged, err := LoadServer()
	if err != nil || !staged.EnableAWSControl || staged.EnableManagedPreparationAWS ||
		staged.WorkerControlEndpointServiceName != "" || staged.InstanceID != instanceID {
		t.Fatalf("staged LoadServer() config=%#v error=%v", staged, err)
	}

	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "true")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME") {
		t.Fatalf("Managed preparation accepted an absent Worker Control service: %v", err)
	}

	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "false")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")
	ready, err := LoadServer()
	if err != nil || ready.InstanceID != instanceID {
		t.Fatalf("ready LoadServer() instance=%q error=%v", ready.InstanceID, err)
	}
}

func TestLoadServerEnablesDirectPublicTLSWithoutPrivateLinkStaging(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "true")
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONNECTIVITY_MODE", "direct_public_tls_v1")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://demo2.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "")

	server, err := LoadServer()
	if err != nil {
		t.Fatal(err)
	}
	if !server.EnableAWSControl || !server.EnableManagedPreparationAWS || server.StagedWorkerControl ||
		server.WorkerConnectivityMode != "direct_public_tls_v1" || server.WorkerControlEndpoint != "grpcs://demo2.dirextalk.ai:443" ||
		server.WorkerControlEndpointServiceName != "" {
		t.Fatalf("direct public TLS config=%#v", server)
	}
}

func TestLoadServerRejectsUnsafeDirectPublicTLSIdentity(t *testing.T) {
	tests := map[string]struct {
		endpoint    string
		serviceName string
	}{
		"private hostname": {endpoint: "grpcs://worker-control.internal:443"},
		"non TLS port":     {endpoint: "grpcs://demo2.dirextalk.ai:9443"},
		"service injection": {
			endpoint:    "grpcs://demo2.dirextalk.ai:443",
			serviceName: "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
			t.Setenv("AGENT_WORKER_CONNECTIVITY_MODE", "direct_public_tls_v1")
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", test.endpoint)
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", test.serviceName)
			if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "direct public Worker control") {
				t.Fatalf("endpoint=%q service=%q error=%v", test.endpoint, test.serviceName, err)
			}
		})
	}
}

func TestLoadServerRejectsMalformedWorkerControlServiceDuringStagedUpgrade(t *testing.T) {
	for _, serviceName := range []string{
		"com.amazonaws.vpce.us-east-1.vpce-svc-0123456789abcdef0",
		"com.amazonaws.vpce.ap-northeast-3.vpce-svc-ABCDEF01234567890",
		"com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef",
	} {
		t.Run(serviceName, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
			t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "false")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", serviceName)
			if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME") {
				t.Fatalf("service %q error=%v", serviceName, err)
			}
		})
	}
}

func TestLoadServerRejectsInvalidAWSControlFlagOrMissingImage(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "yes")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatalf("invalid flag error=%v", err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "AGENT_AWS_REAPER_IMAGE_URI is required") {
		t.Fatalf("missing image error=%v", err)
	}
}

func TestLoadServerAppliesBoundedTwoCoreTwoGiBLocalRunDefaults(t *testing.T) {
	setValidServerEnvironment(t)
	server, err := LoadServer()
	if err != nil {
		t.Fatal(err)
	}
	if server.MaxActiveLocalRuns != 2 || server.MaxBackgroundLocalRuns != 1 || server.GoMemoryLimitBytes != 768*1024*1024 {
		t.Fatalf("default local budget = active:%d background:%d memory:%d", server.MaxActiveLocalRuns, server.MaxBackgroundLocalRuns, server.GoMemoryLimitBytes)
	}

	t.Setenv("AGENT_MAX_ACTIVE_LOCAL_RUNS", "4")
	t.Setenv("AGENT_MAX_BACKGROUND_LOCAL_RUNS", "2")
	t.Setenv("AGENT_GO_MEMORY_LIMIT_MIB", "1536")
	server, err = LoadServer()
	if err != nil {
		t.Fatal(err)
	}
	if server.MaxActiveLocalRuns != 4 || server.MaxBackgroundLocalRuns != 2 || server.GoMemoryLimitBytes != 1536*1024*1024 {
		t.Fatalf("configured local budget = %#v", server)
	}
}

func TestLoadServerRejectsUnsafeLocalRunBudget(t *testing.T) {
	tests := map[string]struct {
		name  string
		value string
	}{
		"zero active":         {name: "AGENT_MAX_ACTIVE_LOCAL_RUNS", value: "0"},
		"negative background": {name: "AGENT_MAX_BACKGROUND_LOCAL_RUNS", value: "-1"},
		"small heap":          {name: "AGENT_GO_MEMORY_LIMIT_MIB", value: "255"},
		"malformed":           {name: "AGENT_MAX_ACTIVE_LOCAL_RUNS", value: "many"},
	}
	for label, test := range tests {
		t.Run(label, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv(test.name, test.value)
			if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), test.name) {
				t.Fatalf("%s=%q error=%v", test.name, test.value, err)
			}
		})
	}
	t.Run("background exceeds total", func(t *testing.T) {
		setValidServerEnvironment(t)
		t.Setenv("AGENT_MAX_ACTIVE_LOCAL_RUNS", "1")
		t.Setenv("AGENT_MAX_BACKGROUND_LOCAL_RUNS", "2")
		if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "must not exceed") {
			t.Fatalf("background/total error=%v", err)
		}
	})
}

func TestValidateMountedSecretFileRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMountedSecretFile(path); err == nil {
		t.Fatal("expected loose permissions to be rejected")
	}
}

func writeSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setValidServerEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MASTER_KEY_FILE", "master-key")
}

func setTeamTrustEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv(
		"AGENT_RUNTIME_CATALOG_FILE",
		"/run/dirextalk/config/runtime-catalog.json",
	)
	t.Setenv(
		"AGENT_RUNTIME_CATALOG_PUBLIC_KEY_FILE",
		"/run/dirextalk/config/runtime-catalog-public-key",
	)
	t.Setenv(
		"AGENT_TEAM_POLICY_FILE",
		"/run/dirextalk/config/team-policy.json",
	)
}

func setTeamPricingCatalogEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv(
		"AGENT_TEAM_MODEL_OFFER_CATALOG_FILE",
		"/run/dirextalk/config/team-model-offers.json",
	)
	t.Setenv(
		"AGENT_TEAM_COMPUTE_CATALOG_FILE",
		"/run/dirextalk/config/team-compute.json",
	)
}

func setAWSControlEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	t.Setenv(
		"AGENT_AWS_REAPER_IMAGE_URI",
		"registry.example/reaper:v0.1.0-alpha.1@sha256:"+
			strings.Repeat("d", 64),
	)
	t.Setenv(
		"AGENT_WORKER_CONNECTIVITY_MODE",
		"direct_public_tls_v1",
	)
	t.Setenv(
		"AGENT_WORKER_CONTROL_ENDPOINT",
		"grpcs://worker-control.y1.dirextalk.ai:443",
	)
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "")
}
