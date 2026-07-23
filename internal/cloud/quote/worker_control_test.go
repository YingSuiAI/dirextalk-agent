package quote

import "testing"

func TestValidateWorkerControlTransportAcceptsDirectPublicTLSOnlyForPublicDNS(t *testing.T) {
	const endpoint = "grpcs://demo2.dirextalk.ai:443"
	if err := ValidateWorkerControlTransport(PrivateConnectivityDirectPublicTLSV1, endpoint, ""); err != nil {
		t.Fatalf("valid direct public TLS transport: %v", err)
	}

	invalid := map[string]struct {
		endpoint    string
		serviceName string
	}{
		"endpoint service injection": {endpoint: endpoint, serviceName: "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0"},
		"localhost":                  {endpoint: "grpcs://localhost:443"},
		"single label":               {endpoint: "grpcs://worker-control:443"},
		"local suffix":               {endpoint: "grpcs://worker-control.local:443"},
		"internal suffix":            {endpoint: "grpcs://worker-control.internal:443"},
		"IPv4 literal":               {endpoint: "grpcs://203.0.113.10:443"},
		"IPv6 literal":               {endpoint: "grpcs://[2001:db8::10]:443"},
		"non TLS port":               {endpoint: "grpcs://demo2.dirextalk.ai:9443"},
		"embedded credential":        {endpoint: "grpcs://worker:secret@demo2.dirextalk.ai:443"},
		"query injection":            {endpoint: "grpcs://demo2.dirextalk.ai:443?target=other"},
	}
	for name, test := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateWorkerControlTransport(PrivateConnectivityDirectPublicTLSV1, test.endpoint, test.serviceName); err == nil {
				t.Fatalf("accepted endpoint=%q service=%q", test.endpoint, test.serviceName)
			}
		})
	}
}

func TestValidateWorkerControlTransportPreservesFrozenPrivateLinkIdentity(t *testing.T) {
	const serviceName = "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0"
	if err := ValidateWorkerControlTransport(PrivateConnectivityNoNATEndpointsV1, WorkerControlPrivateLinkEndpoint, serviceName); err != nil {
		t.Fatalf("valid frozen PrivateLink transport: %v", err)
	}
	if err := ValidateWorkerControlTransport(PrivateConnectivityNoNATEndpointsV1, "grpcs://demo2.dirextalk.ai:443", serviceName); err == nil {
		t.Fatal("PrivateLink mode accepted a different DNS identity")
	}
}
