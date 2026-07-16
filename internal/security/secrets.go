package security

import "regexp"

var likelySecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bDTX-Service-Key\s+[A-Za-z0-9_-]{1,128}\.[A-Za-z0-9_-]{43}\b`),
	regexp.MustCompile(`\bsvc_[A-Za-z0-9_-]{1,123}\.[A-Za-z0-9_-]{43}\b`),
	regexp.MustCompile(`(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`(?i)\b(?:password|client_secret|api_key|access_token|aws_session_token|aws_secret_access_key)\s*[:=]\s*["']?[^\s"',;]{8,}`),
	regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^:/\s]+:[^@/\s]{4,}@`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

var redactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bDTX-Service-Key\s+[A-Za-z0-9_-]{1,128}\.[A-Za-z0-9_-]{43}\b`),
	regexp.MustCompile(`\bsvc_[A-Za-z0-9_-]{1,123}\.[A-Za-z0-9_-]{43}\b`),
	regexp.MustCompile(`(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`(?i)\b(?:password|client_secret|api_key|access_token|aws_session_token|aws_secret_access_key)\s*[:=]\s*["']?[^\s"',;]{4,}`),
}

var userInfoPattern = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)[^@/\s]+@`)

// ContainsLikelySecret protects ordinary control-plane inputs. Secret material
// must use the encrypted bootstrap service instead.
func ContainsLikelySecret(value string) bool {
	for _, pattern := range likelySecretPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func RedactText(value string) string {
	redacted := value
	for _, pattern := range redactionPatterns {
		redacted = pattern.ReplaceAllString(redacted, "[redacted]")
	}
	redacted = userInfoPattern.ReplaceAllString(redacted, "${1}[redacted]@")
	return redacted
}
