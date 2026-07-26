package recipe

// EqualSourceClaims compares canonical source collections by value. SourceV1
// contains an optional repository pointer, so direct struct or slice equality
// would incorrectly treat independently decoded copies as different claims.
func EqualSourceClaims(left, right []SourceV1) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalSourceClaim(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalSourceClaim(left, right SourceV1) bool {
	if left.ID != right.ID ||
		left.URL != right.URL ||
		left.ArtifactURL != right.ArtifactURL ||
		left.Version != right.Version ||
		left.Commit != right.Commit ||
		left.ArtifactDigest != right.ArtifactDigest ||
		left.ContentDigest != right.ContentDigest ||
		left.License != right.License ||
		!left.RetrievedAt.Equal(right.RetrievedAt) ||
		left.Official != right.Official ||
		left.Kind != right.Kind {
		return false
	}
	if left.Repository == nil || right.Repository == nil {
		return left.Repository == nil && right.Repository == nil
	}
	return *left.Repository == *right.Repository
}
