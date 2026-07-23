package quote

import "fmt"

// ValidateWorkerControlTransport validates operator-owned process
// configuration before it can be copied into a Quote or launch intent.
// PrivateLink keeps its frozen service identity; direct public TLS accepts no
// endpoint-service name and relies on the signed public DNS endpoint.
func ValidateWorkerControlTransport(mode PrivateConnectivityMode, endpoint, serviceName string) error {
	switch mode {
	case PrivateConnectivityNoNATEndpointsV1:
		return ValidateWorkerControlPrivateLink(endpoint, serviceName)
	case PrivateConnectivityDirectPublicTLSV1:
		if serviceName != "" || ValidateDirectPublicControlPlaneEndpoint(endpoint) != nil {
			return fmt.Errorf("direct public Worker control identity is invalid")
		}
		return nil
	default:
		return fmt.Errorf("Worker control connectivity mode is invalid")
	}
}
