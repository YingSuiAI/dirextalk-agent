package healthprobe

import "github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"

// EvidenceDigest returns a deterministic digest suitable for a public read
// model without exposing the target or any transport observation details.
func EvidenceDigest(suite SuiteV1, evidence SuiteEvidence) (string, error) {
	if err := ValidateSuiteEvidence(suite, evidence); err != nil {
		return "", err
	}
	digest, err := canonical.Digest(evidence)
	if err != nil {
		return "", ErrInvalidEvidence
	}
	return digest, nil
}
