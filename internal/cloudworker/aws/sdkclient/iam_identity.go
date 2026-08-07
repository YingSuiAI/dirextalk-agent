package sdkclient

import (
	"context"
	"errors"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func (client *Client) ResolveIAMResourceIdentities(
	ctx context.Context,
	request cloudaws.ResolveIAMResourceIdentitiesRequest,
) (cloudaws.IAMResourceIdentityProof, error) {
	if request.Identity.Validate() != nil || request.Plan.Validate() != nil || !request.Plan.Identity.Equal(request.Identity) ||
		request.PlanDigest != request.Plan.Digest || request.InfrastructureDigest != request.Plan.InfrastructureDigest ||
		request.IntentDigest == "" || request.StackProviderID == "" ||
		!containsTags(request.ExpectedTags, cloudaws.RequiredTags(request.Identity, request.PlanDigest, request.InfrastructureDigest, request.IntentDigest)) ||
		!client.matchesConfig(request.Identity) {
		return cloudaws.IAMResourceIdentityProof{}, cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return cloudaws.IAMResourceIdentityProof{}, err
	}
	stack, found, err := client.describeStack(ctx, request.Identity, request.StackProviderID)
	if err != nil || !found {
		return cloudaws.IAMResourceIdentityProof{}, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	if err := client.validateStack(stack, deterministicStackName(request.Identity), request.StackProviderID, request.ExpectedTags); err != nil {
		return cloudaws.IAMResourceIdentityProof{}, err
	}
	mapping, err := client.readStackMapping(ctx, request.Identity, stack, request.ExpectedTags, true)
	if err != nil {
		return cloudaws.IAMResourceIdentityProof{}, err
	}
	roleName := mapping.physical[cloudaws.ResourceIAMRole]
	profileName := mapping.physical[cloudaws.ResourceInstanceProfile]
	if roleName != request.Plan.IAMRoleName || profileName != request.Plan.InstanceProfileName {
		return cloudaws.IAMResourceIdentityProof{}, cloudaws.ErrOwnershipMismatch
	}
	role, found, err := client.getRole(ctx, request.Identity, roleName)
	if err != nil || !found {
		return cloudaws.IAMResourceIdentityProof{}, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	profile, found, err := client.getInstanceProfile(ctx, request.Identity, profileName)
	if err != nil || !found {
		return cloudaws.IAMResourceIdentityProof{}, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	roleID := awssdk.ToString(role.RoleId)
	profileID := awssdk.ToString(profile.InstanceProfileId)
	if !validIAMUniqueID(roleID) || !validIAMUniqueID(profileID) || len(profile.Roles) != 1 ||
		awssdk.ToString(profile.Roles[0].RoleName) != roleName || awssdk.ToString(profile.Roles[0].RoleId) != roleID {
		return cloudaws.IAMResourceIdentityProof{}, cloudaws.ErrOwnershipMismatch
	}
	roleTags, err := client.listRoleTags(ctx, request.Identity, roleName)
	if err != nil || !containsTags(roleTags, request.ExpectedTags) {
		return cloudaws.IAMResourceIdentityProof{}, errors.Join(cloudaws.ErrOwnershipMismatch, err)
	}
	return cloudaws.IAMResourceIdentityProof{
		Identity: request.Identity, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
		IntentDigest: request.IntentDigest, StackProviderID: request.StackProviderID,
		IAMRoleName: roleName, IAMRoleID: roleID, InstanceProfileName: profileName,
		InstanceProfileID: profileID, ObservedAt: client.now().UTC(),
	}, nil
}

func (client *Client) ensureIAMProofMatches(
	ctx context.Context,
	request cloudaws.EnsureResourceIdentityRequest,
) (cloudaws.IAMResourceIdentityProof, error) {
	proof, err := client.ResolveIAMResourceIdentities(ctx, cloudaws.ResolveIAMResourceIdentitiesRequest{
		Identity: request.Identity, Plan: request.Plan, PlanDigest: request.PlanDigest,
		InfrastructureDigest: request.InfrastructureDigest, IntentDigest: request.IntentDigest,
		StackProviderID: request.StackProviderID, ExpectedTags: request.ExpectedTags,
	})
	if err != nil {
		return cloudaws.IAMResourceIdentityProof{}, err
	}
	if proof.IAMRoleID != request.ExpectedResourceProviderIDs[cloudaws.ResourceIAMRole] ||
		proof.InstanceProfileID != request.ExpectedResourceProviderIDs[cloudaws.ResourceInstanceProfile] {
		return cloudaws.IAMResourceIdentityProof{}, cloudaws.ErrOwnershipMismatch
	}
	return proof, nil
}

func (client *Client) ensureInstanceProfileIdentity(ctx context.Context, request cloudaws.EnsureResourceIdentityRequest) error {
	proof, err := client.ensureIAMProofMatches(ctx, request)
	if err != nil {
		return err
	}
	profileTags, err := client.listInstanceProfileTags(ctx, request.Identity, proof.InstanceProfileName)
	if err != nil {
		return err
	}
	if containsTags(profileTags, request.ExpectedTags) {
		return nil
	}
	// Re-read both immutable IDs immediately before the only name-addressed IAM
	// write. A same-name replacement after the durable ledger binding fails
	// closed and TagInstanceProfile is never called.
	proof, err = client.ensureIAMProofMatches(ctx, request)
	if err != nil {
		return err
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return err
	}
	_, err = client.iam.TagInstanceProfile(ctx, &iam.TagInstanceProfileInput{
		InstanceProfileName: awssdk.String(proof.InstanceProfileName), Tags: sdkIAMTags(request.ExpectedTags),
	})
	if err != nil {
		return errors.Join(cloudaws.ErrResponseUnknown, err)
	}
	profileTags, err = client.listInstanceProfileTags(ctx, request.Identity, proof.InstanceProfileName)
	if err != nil || !containsTags(profileTags, request.ExpectedTags) {
		return errors.Join(cloudaws.ErrResponseUnknown, err)
	}
	if _, err = client.ensureIAMProofMatches(ctx, request); err != nil {
		return errors.Join(cloudaws.ErrResponseUnknown, err)
	}
	return nil
}

func validIAMUniqueID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
