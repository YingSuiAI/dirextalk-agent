package postgres

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

// TestCoreAWSRealProviderLifecycle is intentionally opt-in. It must only be
// enabled against a disposable account with a credential CSV supplied at
// runtime; no credential material is checked into the repository.
func TestCoreAWSRealProviderLifecycle(t *testing.T) {
	if os.Getenv("DIREXTALK_REAL_AWS_ACCEPTANCE") != "1" {
		t.Skip("real AWS acceptance is opt-in")
	}
	if strings.TrimSpace(os.Getenv("DIREXTALK_COREV1_TEST_DSN")) == "" {
		t.Skip("Core v1 test DSN is required")
	}
	region := strings.TrimSpace(os.Getenv("DIREXTALK_REAL_AWS_REGION"))
	if region == "" {
		region = "us-east-1"
	}
	expectedAccountID := strings.TrimSpace(os.Getenv("DIREXTALK_REAL_AWS_ACCOUNT_ID"))
	if !isRealAWSAccountID(expectedAccountID) {
		t.Fatal("DIREXTALK_REAL_AWS_ACCOUNT_ID must be exactly 12 digits")
	}
	accessKey, secretKey, sessionToken, ok := readRealAWSCredentialCSV()
	if !ok {
		t.Skip("runtime AWS credential CSV is unavailable or invalid")
	}
	verificationConfig := realAWSConfig(region, accessKey, secretKey, sessionToken)
	identity, err := sts.NewFromConfig(verificationConfig).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil || identity == nil || aws.ToString(identity.Account) != expectedAccountID {
		if err != nil {
			t.Fatalf("verify selected real AWS account: %v", err)
		}
		t.Fatalf("selected real AWS account %q does not match DIREXTALK_REAL_AWS_ACCOUNT_ID", aws.ToString(identity.Account))
	}

	_, store, _, cleanup := corePGFixture(t, strings.TrimSpace(os.Getenv("DIREXTALK_COREV1_TEST_DSN")))
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ctx, err = coreaws.WithCredentialMutationScope(ctx, coreteam.Scope{OwnerID: "@real-aws-acceptance:example.test", AccountGeneration: 1})
	if err != nil {
		t.Fatal("bind real AWS acceptance credential scope")
	}
	awsStore := NewCoreAWSStore(store)
	coord := NewCoreAWSChangeCoordinator(store, time.Now)
	confirmDomain, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal("initialize confirmation service")
	}
	provider, err := coreaws.NewSDKProvider(coreaws.NewSDKFactory(), coreaws.WithSDKTimeout(2*time.Minute))
	if err != nil {
		t.Fatal("initialize AWS provider")
	}
	domain := coreaws.NewServiceWithCoordinator(awsStore, coord, confirmDomain, nil, provider, provider, time.Now)
	cloudRPC, err := rpcapi.NewCoreCloudControlService(domain)
	if err != nil {
		t.Fatal("initialize cloud RPC")
	}
	confirmRPC, err := rpcapi.NewCoreConfirmationService(confirmDomain)
	if err != nil {
		t.Fatal("initialize confirmation RPC")
	}
	tasks := NewCoreTaskStore(store)
	handler, err := coreruntime.NewAWSChangeTaskHandler(domain, coord)
	if err != nil {
		t.Fatal("initialize AWS task handler")
	}

	stackName := "dirextalk-corev1-" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	cleanupClient := cloudformation.NewFromConfig(verificationConfig)
	queueClient := sqs.NewFromConfig(verificationConfig)
	agentDeleteDone := false
	defer func() {
		if agentDeleteDone {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if _, err := cleanupClient.DeleteStack(cleanupCtx, &cloudformation.DeleteStackInput{StackName: aws.String(stackName), ClientRequestToken: aws.String(uuid.NewString())}); err != nil {
			t.Errorf("fallback real AWS cleanup DeleteStack failed (account=%s region=%s stack=%s): %v", expectedAccountID, region, stackName, err)
		}
		if err := waitForRealStackDeletion(cleanupCtx, cleanupClient, stackName); err != nil {
			t.Errorf("fallback real AWS cleanup deletion verification failed (account=%s region=%s stack=%s): %v", expectedAccountID, region, stackName, err)
		}
	}()
	t.Logf("real AWS acceptance target selected: account=%s region=%s stack=%s", expectedAccountID, region, stackName)

	credResp, err := cloudRPC.CreateCredential(ctx, &agentv1.CoreCloudControlServiceCreateCredentialRequest{IdempotencyKey: uuid.NewString(), Name: "corev1-real-acceptance", Region: region, AccessKeyId: accessKey, SecretAccessKey: secretKey, SessionToken: sessionToken})
	if err != nil || credResp.GetCredential() == nil {
		t.Fatal("save runtime AWS credential")
	}
	credID := credResp.GetCredential().GetCredentialId()
	if _, err = cloudRPC.TestCredentialIdentity(ctx, &agentv1.CoreCloudControlServiceTestCredentialIdentityRequest{CredentialId: credID}); err != nil {
		t.Fatal("verify runtime AWS credential identity")
	}
	template := []byte(`{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Properties":{"Tags":[{"Key":"dirextalk_corev1","Value":"real-acceptance"},{"Key":"ephemeral","Value":"true"}]}}}}`)
	planResp, err := cloudRPC.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{IdempotencyKey: uuid.NewString(), CredentialId: credID, Region: region, StackName: stackName, Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_CREATE, Template: template, Tags: map[string]string{"dirextalk_corev1": "real-acceptance", "ephemeral": "true"}})
	if err != nil || planResp.GetPlan() == nil {
		t.Fatal("create real AWS plan")
	}
	createReq, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: uuid.NewString(), PlanId: planResp.GetPlan().GetPlanId()})
	if err != nil || createReq.GetConfirmation() == nil {
		t.Fatal("request real AWS create confirmation")
	}
	if _, err = confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: createReq.GetConfirmation().GetConfirmationId(), IdempotencyKey: uuid.NewString(), ExpectedRevision: createReq.GetConfirmation().GetRevision()}); err != nil {
		t.Fatal("confirm real AWS create")
	}
	claimed, _, err := tasks.ClaimNextDue(ctx, "real-aws-acceptance", time.Now().UTC(), 5*time.Minute, 1)
	if err != nil {
		t.Fatal("claim real AWS create task")
	}
	if err = driveRealAWSChange(ctx, domain, handler, tasks, claimed, createReq.GetConfirmation().GetConfirmationId()); err != nil {
		t.Fatalf("execute real AWS create task: %v", err)
	}
	if err = waitForRealStack(ctx, cleanupClient, stackName, "CREATE_COMPLETE"); err != nil {
		t.Fatal("wait for real AWS stack creation")
	}
	if err = verifyRealQueueStack(ctx, cleanupClient, queueClient, stackName); err != nil {
		t.Fatal("independent real AWS stack and queue verification")
	}
	t.Log("real AWS stack and SQS queue independently verified after create")

	deletePlan, err := cloudRPC.CreatePlan(ctx, &agentv1.CoreCloudControlServiceCreatePlanRequest{IdempotencyKey: uuid.NewString(), CredentialId: credID, Region: region, StackName: stackName, Operation: agentv1.CoreAWSOperation_CORE_AWS_OPERATION_DELETE, Template: template, Tags: map[string]string{"dirextalk_corev1": "real-acceptance", "ephemeral": "true"}})
	if err != nil || deletePlan.GetPlan() == nil {
		t.Fatal("create real AWS delete plan")
	}
	deleteReq, err := cloudRPC.RequestChange(ctx, &agentv1.CoreCloudControlServiceRequestChangeRequest{IdempotencyKey: uuid.NewString(), PlanId: deletePlan.GetPlan().GetPlanId()})
	if err != nil || deleteReq.GetConfirmation() == nil {
		t.Fatal("request real AWS delete confirmation")
	}
	if _, err = confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: deleteReq.GetConfirmation().GetConfirmationId(), IdempotencyKey: uuid.NewString(), ExpectedRevision: deleteReq.GetConfirmation().GetRevision()}); err != nil {
		t.Fatal("confirm real AWS delete")
	}
	deleteTask, _, err := tasks.ClaimNextDue(ctx, "real-aws-acceptance-delete", time.Now().UTC(), 5*time.Minute, 1)
	if err != nil {
		t.Fatal("claim real AWS delete task")
	}
	if err = driveRealAWSChange(ctx, domain, handler, tasks, deleteTask, deleteReq.GetConfirmation().GetConfirmationId()); err != nil {
		t.Fatalf("execute real AWS delete task: %v", err)
	}
	if err = waitForRealStackDeletion(ctx, cleanupClient, stackName); err != nil {
		t.Fatal("independent real AWS deletion verification")
	}
	t.Log("real AWS stack deletion independently verified")
	agentDeleteDone = true
}

func driveRealAWSChange(ctx context.Context, domain *coreaws.Service, handler coreruntime.TaskHandler, tasks *CoreTaskStore, claimed coretask.Task, confirmationID string) error {
	outcome := handler(ctx, claimed)
	if outcome.Err != nil && !errors.Is(outcome.Err, coreaws.ErrResponseUncertain) {
		return outcome.Err
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		change, pollErr := domain.PollChange(ctx, confirmationID)
		if pollErr != nil && !errors.Is(pollErr, coreaws.ErrResponseUncertain) {
			return pollErr
		}
		if change.Status == coreaws.ChangeSucceeded || change.Status == coreaws.ChangeFailed || change.Status == coreaws.ChangeCanceled {
			task, taskErr := tasks.GetTask(ctx, claimed.ID)
			if taskErr != nil {
				return taskErr
			}
			if task.Status != "succeeded" && task.Status != "failed" {
				return errors.New("AWS change terminalized without a terminal task")
			}
			if change.Status != coreaws.ChangeSucceeded {
				return errors.New("AWS change terminalized unsuccessfully")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("AWS change did not reach a durable terminal state")
		case <-ticker.C:
		}
	}
}

func isRealAWSAccountID(accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, r := range accountID {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func readRealAWSCredentialCSV() (string, string, string, bool) {
	path := strings.TrimSpace(os.Getenv("DIREXTALK_REAL_AWS_CREDENTIAL_CSV"))
	if path == "" {
		return "", "", "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", false
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || len(records) < 1 {
		return "", "", "", false
	}
	access, secret, session := -1, -1, -1
	for i, name := range records[0] {
		name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
		switch strings.ToLower(name) {
		case "access key id", "access_key_id", "accesskeyid":
			access = i
		case "secret access key", "secret_access_key", "secretaccesskey":
			secret = i
		case "session token", "session_token", "sessiontoken":
			session = i
		}
	}
	row := records[0]
	if access < 0 || secret < 0 {
		if len(records) < 2 || len(records[0]) < 2 {
			return "", "", "", false
		}
		row, access, secret = records[0], 0, 1
	} else if len(records) >= 2 {
		row = records[1]
	} else {
		return "", "", "", false
	}
	if access >= len(row) || secret >= len(row) || strings.TrimSpace(row[access]) == "" || strings.TrimSpace(row[secret]) == "" {
		return "", "", "", false
	}
	if session >= 0 && session < len(row) {
		return strings.TrimSpace(row[access]), strings.TrimSpace(row[secret]), strings.TrimSpace(row[session]), true
	}
	return strings.TrimSpace(row[access]), strings.TrimSpace(row[secret]), "", true
}

func realAWSConfig(region, accessKey, secretKey, sessionToken string) aws.Config {
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	return aws.Config{Region: region, Credentials: aws.NewCredentialsCache(provider)}
}

func waitForRealStack(ctx context.Context, client *cloudformation.Client, stackName, want string) error {
	deadline := time.NewTicker(5 * time.Second)
	defer deadline.Stop()
	for {
		out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
		if err == nil && out != nil && len(out.Stacks) == 1 {
			status := string(out.Stacks[0].StackStatus)
			if status == want {
				return nil
			}
			if strings.HasSuffix(status, "_FAILED") {
				return errors.New("real AWS stack entered a failed state")
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("real AWS stack did not reach expected state")
		case <-deadline.C:
		}
	}
}

func waitForRealStackDeletion(ctx context.Context, client *cloudformation.Client, stackName string) error {
	deadline := time.NewTicker(5 * time.Second)
	defer deadline.Stop()
	for {
		_, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
		if isRealStackNotFound(err) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("real AWS stack deletion was not independently verified")
		case <-deadline.C:
		}
	}
}

func verifyRealQueueStack(ctx context.Context, client *cloudformation.Client, queueClient *sqs.Client, stackName string) error {
	stacks, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
	if err != nil || stacks == nil || len(stacks.Stacks) != 1 || string(stacks.Stacks[0].StackStatus) != "CREATE_COMPLETE" {
		return errors.New("real AWS stack read-back failed")
	}
	resources, err := client.DescribeStackResources(ctx, &cloudformation.DescribeStackResourcesInput{StackName: aws.String(stackName)})
	if err != nil || resources == nil || len(resources.StackResources) != 1 {
		return errors.New("real AWS queue resource read-back failed")
	}
	resource := resources.StackResources[0]
	queueURL := aws.ToString(resource.PhysicalResourceId)
	if aws.ToString(resource.ResourceType) != "AWS::SQS::Queue" || queueURL == "" {
		return errors.New("real AWS stack did not contain exactly one SQS queue")
	}
	tags, err := queueClient.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: aws.String(queueURL)})
	if err != nil || tags == nil || tags.Tags["dirextalk_corev1"] != "real-acceptance" || tags.Tags["ephemeral"] != "true" {
		return errors.New("real AWS SQS queue read-back failed")
	}
	return nil
}

func isRealStackNotFound(err error) bool {
	var apiErr smithy.APIError
	return err != nil && errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationError" && strings.Contains(strings.ToLower(apiErr.ErrorMessage()), "does not exist")
}
