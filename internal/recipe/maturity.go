package recipe

import "fmt"

// PromoteToManaged binds the exact experimental digest to an external
// verification and device-signed acceptance record. The caller must persist
// those records independently; RecipeV1 deliberately carries only references.
func (r RecipeV1) PromoteToManaged(acceptance ManagedAcceptanceV1) (RecipeV1, error) {
	if r.Maturity != MaturityExperimental || r.ManagedAcceptance != nil {
		return RecipeV1{}, fmt.Errorf("only an experimental recipe without acceptance can be promoted")
	}
	if err := r.Validate(); err != nil {
		return RecipeV1{}, err
	}
	digest, err := r.Digest()
	if err != nil {
		return RecipeV1{}, err
	}
	if acceptance.ExperimentalDigest != "" && acceptance.ExperimentalDigest != digest {
		return RecipeV1{}, fmt.Errorf("managed acceptance binds another experimental recipe")
	}
	acceptance.ExperimentalDigest = digest
	managed := r
	managed.Maturity = MaturityManaged
	managed.ManagedAcceptance = &acceptance
	if err := managed.Validate(); err != nil {
		return RecipeV1{}, err
	}
	return managed, nil
}
