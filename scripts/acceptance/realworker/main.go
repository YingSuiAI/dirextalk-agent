package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const receiptSchema = "dirextalk.agent.worker.acceptance.v1"

type config struct {
	receipt, runDir, httpBase, token, awsProfile, region, modelProfileID string
	timeout, poll                                                        time.Duration
}

type receipt struct {
	Schema     string `json:"schema"`
	Credential struct {
		CreatedByDriver     bool `json:"created_by_driver"`
		PreexistingVerified bool `json:"preexisting_verified"`
		Tested              bool `json:"tested"`
		Listed              bool `json:"listed"`
	} `json:"credential"`
	Catalog struct {
		WorkersServer bool `json:"workers_server"`
	} `json:"catalog"`
	Quote struct {
		Observed bool `json:"observed"`
	} `json:"quote"`
	Confirmation struct {
		Confirmed bool `json:"confirmed"`
	} `json:"confirmation"`
	Worker struct {
		Created        bool `json:"created"`
		StatusObserved bool `json:"status_observed"`
		LoadObserved   bool `json:"load_observed"`
	} `json:"worker"`
	Artifact struct {
		Downloaded bool `json:"downloaded"`
	} `json:"artifact"`
	Reuse struct {
		Completed                 bool `json:"completed"`
		NoNewCreationConfirmation bool `json:"no_new_creation_confirmation"`
	} `json:"reuse"`
	Destroy struct {
		Completed       bool `json:"completed"`
		ResourcesAbsent bool `json:"resources_absent"`
	} `json:"destroy"`
	Evidence struct {
		AccountID        string         `json:"account_id"`
		Region           string         `json:"region"`
		CredentialID     string         `json:"credential_id"`
		ConversationID   string         `json:"conversation_id"`
		FirstPlanID      string         `json:"first_plan_id"`
		FirstExecutionID string         `json:"first_execution_id"`
		ReusePlanID      string         `json:"reuse_plan_id"`
		ReuseExecutionID string         `json:"reuse_execution_id"`
		WorkerIdentity   workerIdentity `json:"worker_identity"`
		ArtifactID       string         `json:"artifact_id"`
		ArtifactSHA256   string         `json:"artifact_sha256"`
	} `json:"evidence"`
	S3Used bool `json:"s3_used"`
}

type credential struct {
	CredentialID     string `json:"credential_id"`
	Region           string `json:"region"`
	AccountID        string `json:"account_id"`
	Revision         int64  `json:"revision"`
	VerifiedRevision int64  `json:"verified_revision"`
	TestedAt         string `json:"tested_at"`
}

type profile struct {
	ProfileID         string `json:"profile_id"`
	ClientProfileID   string `json:"client_profile_id"`
	Provider          string `json:"provider"`
	ModelKind         string `json:"model_kind"`
	APIKeyConfigured  bool   `json:"api_key_configured"`
	Revision          int64  `json:"revision"`
	CredentialVersion int64  `json:"credential_version"`
}

type plan struct {
	PlanID, ExecutionID, ConfirmationID, ConversationID string
	Status                                              string
	Revision                                            int64
	Quote                                               quote
}

type quote struct {
	AmountMicros                            int64
	Currency, Digest, SourceTime, ExpiresAt string
}

type run struct {
	RunID, PlanID, ConversationID, Status, WorkerID, FailureCode, FailureSummary string
	PersistentWorker                                                             bool
	ArtifactIDs                                                                  []string
}

type workerIdentity struct {
	WorkerID           string `json:"worker_id"`
	InstanceID         string `json:"instance_id"`
	KeyPairID          string `json:"key_pair_id"`
	SecurityGroupID    string `json:"security_group_id"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision int64  `json:"credential_revision"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
}

type workerStatus struct {
	Identity                                        workerIdentity
	Availability, EC2State, WorkerPhase, PublicIPv4 string
	Server                                          map[string]any
}

type streamResult struct {
	TurnID, ConfirmationID, ExecutionID string
	Done                                bool
}

type productAPI interface {
	Call(context.Context, string, map[string]any) (map[string]any, error)
	StartTurn(context.Context, map[string]any, bool) (streamResult, error)
}

type cloudIdentity struct {
	AccountID, ARN string
}

type exportedCredential struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

type awsAPI interface {
	Identity(context.Context) (cloudIdentity, error)
	ExportCredential(context.Context) (exportedCredential, error)
	ObserveOwnedResources(context.Context, workerIdentity) error
	ResourcesAbsent(context.Context, workerIdentity) (bool, error)
}

type driver struct {
	cfg     config
	product productAPI
	aws     awsAPI

	createdCredential *credential
	conversationID    string
	worker            *workerIdentity
	confirmedRunID    string
	destroyRequested  bool
	workerAbsent      bool
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	httpProduct, err := newHTTPProduct(cfg.httpBase, cfg.token, cfg.timeout)
	if err != nil {
		fatal(err)
	}
	d := &driver{cfg: cfg, product: httpProduct, aws: &cliAWS{profile: cfg.awsProfile, region: cfg.region}}
	result, err := d.run(ctx)
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), minDuration(cfg.timeout, 10*time.Minute))
		cleanupErr := d.cleanup(cleanupCtx)
		cleanupCancel()
		if cleanupErr != nil {
			fatal(fmt.Errorf("acceptance failed: %w; owned cleanup also failed: %v", err, cleanupErr))
		}
		fatal(fmt.Errorf("acceptance failed: %w", err))
	}
	if err := writeReceiptAtomic(cfg.receipt, result); err != nil {
		fatal(err)
	}
	fmt.Fprintln(os.Stderr, "real Worker acceptance completed; receipt written")
}

func configFromEnv() (config, error) {
	value := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	cfg := config{
		receipt: value("DIREXTALK_ACCEPTANCE_RECEIPT"), runDir: value("DIREXTALK_ACCEPTANCE_RUN_DIR"),
		httpBase: value("DIREXTALK_ACCEPTANCE_HTTP_BASE"), token: value("DIREXTALK_ACCEPTANCE_OWNER_ACCESS_TOKEN"),
		awsProfile: value("DIREXTALK_ACCEPTANCE_AWS_PROFILE"), region: value("DIREXTALK_ACCEPTANCE_AWS_REGION"),
		modelProfileID: value("DIREXTALK_ACCEPTANCE_MODEL_PROFILE_ID"), timeout: 70 * time.Minute, poll: 3 * time.Second,
	}
	if cfg.token == "" {
		path := value("DIREXTALK_ACCEPTANCE_SESSION_FILE")
		var session struct {
			AccessToken string `json:"access_token"`
		}
		body, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(body, &session) != nil {
			return config{}, errors.New("owner access token or readable session file is required")
		}
		cfg.token = strings.TrimSpace(session.AccessToken)
	}
	if cfg.region == "" {
		cfg.region = "ap-east-1"
	}
	if raw := value("DIREXTALK_ACCEPTANCE_REAL_WORKER_TIMEOUT_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 60 || seconds > 7200 {
			return config{}, errors.New("real Worker timeout must be 60..7200 seconds")
		}
		cfg.timeout = time.Duration(seconds) * time.Second
	}
	for name, path := range map[string]string{"receipt": cfg.receipt, "run directory": cfg.runDir} {
		if !filepath.IsAbs(path) {
			return config{}, fmt.Errorf("%s must be absolute", name)
		}
	}
	parsed, err := url.Parse(cfg.httpBase)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || cfg.token == "" || cfg.awsProfile == "" {
		return config{}, errors.New("HTTP base, owner authentication, and explicit AWS profile are required")
	}
	if err := os.MkdirAll(cfg.runDir, 0o700); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (d *driver) run(ctx context.Context) (receipt, error) {
	var out receipt
	out.Schema, out.S3Used = receiptSchema, false

	identity, err := d.aws.Identity(ctx)
	if err != nil || len(identity.AccountID) != 12 {
		return out, fmt.Errorf("AWS profile identity: %w", err)
	}
	credentials, err := d.listCredentials(ctx)
	if err != nil || len(credentials) > 1 {
		return out, fmt.Errorf("sole AWS credential precondition: count=%d: %w", len(credentials), err)
	}
	backend, err := d.product.Call(ctx, "agent.backends.get", map[string]any{})
	if err != nil {
		return out, fmt.Errorf("read backend catalog: %w", err)
	}
	workersReadyBefore := hasWorkersServer(backend)
	if workersReadyBefore {
		workers, listErr := d.listWorkers(ctx)
		if listErr != nil || len(workers) != 0 {
			return out, fmt.Errorf("baseline Worker set must be empty: count=%d: %w", len(workers), listErr)
		}
	} else if len(credentials) != 0 {
		return out, errors.New("Worker catalog is unavailable despite an existing credential; baseline cannot be proven")
	}
	// A retained Worker makes workers.server ready even without a current
	// credential. Therefore no credential plus no workers.server is the public
	// fresh-state proof; no mutation has occurred before this point.

	var current credential
	if len(credentials) == 0 {
		exported, exportErr := d.aws.ExportCredential(ctx)
		if exportErr != nil {
			return out, fmt.Errorf("resolve explicit AWS profile credential: %w", exportErr)
		}
		params := map[string]any{"idempotency_key": uuid4(), "name": "Real Worker acceptance " + marker(), "region": d.cfg.region,
			"access_key_id": exported.AccessKeyID, "secret_access_key": exported.SecretAccessKey}
		if exported.SessionToken != "" {
			params["session_token"] = exported.SessionToken
		}
		response, createErr := d.product.Call(ctx, "agent.core.aws.credentials.create", params)
		params["access_key_id"], params["secret_access_key"], params["session_token"] = "", "", ""
		exported = exportedCredential{}
		if createErr != nil {
			return out, fmt.Errorf("create sole AWS credential: %w", createErr)
		}
		current, err = decodeCredential(object(response, "credential"))
		if err != nil {
			return out, fmt.Errorf("created credential projection: %w", err)
		}
		// A newly saved credential is intentionally unverified, so its create
		// projection has no AWS account yet. Retain the already revalidated
		// explicit-profile account solely for owned failure cleanup; the test/list
		// readback below remains the authority for successful use.
		current.AccountID = identity.AccountID
		d.createdCredential = &current
		if _, err = d.product.Call(ctx, "agent.core.aws.credentials.test", map[string]any{
			"credential_id": current.CredentialID, "expected_revision": current.Revision, "idempotency_key": uuid4(),
		}); err != nil {
			return out, fmt.Errorf("test created credential: %w", err)
		}
		out.Credential.CreatedByDriver = true
	} else {
		current = credentials[0]
		out.Credential.PreexistingVerified = true
	}
	credentials, err = d.listCredentials(ctx)
	if err != nil || len(credentials) != 1 {
		return out, fmt.Errorf("credential readback: count=%d: %w", len(credentials), err)
	}
	current = credentials[0]
	if current.AccountID != identity.AccountID || current.Region != d.cfg.region || current.VerifiedRevision != current.Revision || current.TestedAt == "" {
		return out, errors.New("sole credential is not the exact current verified AWS profile identity")
	}
	if d.createdCredential != nil {
		d.createdCredential = &current
	}
	out.Credential.Tested, out.Credential.Listed = true, true

	backend, err = d.product.Call(ctx, "agent.backends.get", map[string]any{})
	if err != nil || !hasWorkersServer(backend) {
		return out, fmt.Errorf("workers.server catalog readiness: %w", err)
	}
	out.Catalog.WorkersServer = true
	workers, err := d.listWorkers(ctx)
	if err != nil || len(workers) != 0 {
		return out, fmt.Errorf("post-credential baseline Worker set must remain empty: count=%d: %w", len(workers), err)
	}
	selected, err := d.selectProfile(ctx)
	if err != nil {
		return out, err
	}

	d.conversationID = uuid4()
	if _, err = d.product.Call(ctx, "agent.chat.conversations.create", map[string]any{
		"conversation_id": d.conversationID, "idempotency_key": uuid4(), "title": "Real Worker acceptance " + marker(),
	}); err != nil {
		return out, fmt.Errorf("create acceptance conversation: %w", err)
	}
	baselinePlans, err := d.planIDs(ctx)
	if err != nil {
		return out, err
	}
	artifactMarker := "DIREXTALK_WORKER_ACCEPTANCE_" + marker()
	firstStream, err := d.product.StartTurn(ctx, chatParams(selected, d.conversationID,
		firstWorkerPrompt(artifactMarker)), true)
	if err != nil || firstStream.ConfirmationID == "" || firstStream.ExecutionID == "" {
		return out, fmt.Errorf("first durable Worker offer: %w", err)
	}
	firstPlan, err := d.findNewPlan(ctx, baselinePlans, d.conversationID, firstStream.ExecutionID)
	if err != nil {
		return out, err
	}
	if firstPlan.ConfirmationID != firstStream.ConfirmationID || firstPlan.Status != "waiting_user" || !validPricedQuote(firstPlan.Quote) {
		return out, errors.New("first plan did not expose the exact pending priced offer")
	}
	out.Quote.Observed = true
	confirmation, err := d.pendingConfirmation(ctx, firstPlan)
	if err != nil {
		return out, err
	}
	if err = d.revalidateAccount(ctx, identity.AccountID); err != nil {
		return out, fmt.Errorf("pre-confirm AWS identity: %w", err)
	}
	confirmed, err := d.product.Call(ctx, "agent.core.confirmations.confirm", map[string]any{
		"confirmation_id": firstPlan.ConfirmationID, "expected_revision": integer(confirmation["revision"]), "idempotency_key": uuid4(),
	})
	if err != nil || stringValue(object(confirmed, "confirmation"), "state") != "confirmed" {
		return out, fmt.Errorf("confirm exact first offer: %w", err)
	}
	d.confirmedRunID = firstPlan.ExecutionID
	out.Confirmation.Confirmed = true
	firstRun, err := d.waitRun(ctx, firstPlan.ExecutionID)
	if err != nil {
		return out, err
	}
	if !firstRun.PersistentWorker || firstRun.PlanID != firstPlan.PlanID || firstRun.WorkerID == "" || len(firstRun.ArtifactIDs) == 0 {
		return out, errors.New("first successful run lacks retained Worker or artifact identity")
	}
	worker, err := d.waitWorker(ctx, firstRun.WorkerID)
	if err != nil {
		return out, err
	}
	if worker.Identity.CredentialID != current.CredentialID || worker.Identity.AccountID != identity.AccountID || worker.Identity.Region != d.cfg.region {
		return out, errors.New("created Worker credential/account/region identity drifted")
	}
	d.worker = &worker.Identity
	out.Worker.Created, out.Worker.StatusObserved, out.Worker.LoadObserved = true, true, true
	artifactID, artifactSHA, err := d.downloadMarkedArtifact(ctx, firstRun, artifactMarker)
	if err != nil {
		return out, err
	}
	out.Artifact.Downloaded = true
	if err = d.waitTurn(ctx, firstStream.TurnID); err != nil {
		return out, err
	}

	secondBaseline, err := d.planIDs(ctx)
	if err != nil {
		return out, err
	}
	secondStream, err := d.product.StartTurn(ctx, chatParams(selected, d.conversationID,
		reuseWorkerPrompt()), false)
	if err != nil || !secondStream.Done {
		return out, fmt.Errorf("retained Worker reuse turn: %w", err)
	}
	secondPlan, err := d.findNewPlan(ctx, secondBaseline, d.conversationID, "")
	if err != nil {
		return out, err
	}
	if secondPlan.PlanID == firstPlan.PlanID || secondPlan.Quote.AmountMicros != 0 || secondPlan.Quote.Currency != "USD" || secondPlan.Quote.Digest == "" {
		return out, errors.New("second task did not expose a zero-priced retained Worker reuse plan")
	}
	pending, err := d.listConfirmations(ctx, secondPlan.ExecutionID, []string{"pending"})
	if err != nil || len(pending) != 0 {
		return out, fmt.Errorf("reuse created a pending Worker creation confirmation: count=%d: %w", len(pending), err)
	}
	secondRun, err := d.waitRun(ctx, secondPlan.ExecutionID)
	if err != nil {
		return out, err
	}
	workers, err = d.listWorkers(ctx)
	if err != nil || len(workers) != 1 || workers[0].Identity != worker.Identity || secondRun.WorkerID != worker.Identity.WorkerID {
		return out, fmt.Errorf("reuse did not retain the exact one Worker identity: count=%d: %w", len(workers), err)
	}
	out.Reuse.Completed, out.Reuse.NoNewCreationConfirmation = true, true

	if err = d.revalidateAccount(ctx, identity.AccountID); err != nil {
		return out, fmt.Errorf("pre-destroy AWS identity: %w", err)
	}
	if err = d.aws.ObserveOwnedResources(ctx, worker.Identity); err != nil {
		return out, fmt.Errorf("pre-destroy exact resource ownership: %w", err)
	}
	if _, err = d.product.Call(ctx, "agent.workers.destroy", map[string]any{"identity": identityMap(worker.Identity), "confirmation": "destroy_worker"}); err != nil {
		return out, fmt.Errorf("destroy exact Worker: %w", err)
	}
	d.destroyRequested = true
	if err = d.waitWorkerAbsent(ctx, worker.Identity); err != nil {
		return out, err
	}
	absent, err := d.aws.ResourcesAbsent(ctx, worker.Identity)
	if err != nil || !absent {
		return out, fmt.Errorf("exact AWS resource absence: %w", err)
	}
	d.workerAbsent = true
	out.Destroy.Completed, out.Destroy.ResourcesAbsent = true, true

	conversationEvidence := d.conversationID
	if err = d.cleanupRecords(ctx); err != nil {
		return out, err
	}
	out.Evidence.AccountID, out.Evidence.Region = identity.AccountID, d.cfg.region
	out.Evidence.CredentialID, out.Evidence.ConversationID = current.CredentialID, conversationEvidence
	out.Evidence.FirstPlanID, out.Evidence.FirstExecutionID = firstPlan.PlanID, firstPlan.ExecutionID
	out.Evidence.ReusePlanID, out.Evidence.ReuseExecutionID = secondPlan.PlanID, secondPlan.ExecutionID
	out.Evidence.WorkerIdentity = worker.Identity
	out.Evidence.ArtifactID, out.Evidence.ArtifactSHA256 = artifactID, artifactSHA
	return out, nil
}

func (d *driver) cleanup(ctx context.Context) error {
	var failures []error
	if d.worker == nil && d.confirmedRunID != "" {
		if current, err := d.getRun(ctx, d.confirmedRunID); err == nil && current.WorkerID != "" {
			workers, listErr := d.listWorkers(ctx)
			if listErr != nil {
				failures = append(failures, listErr)
			} else {
				for _, candidate := range workers {
					if candidate.Identity.WorkerID == current.WorkerID {
						identity := candidate.Identity
						d.worker = &identity
						break
					}
				}
			}
		}
		if d.worker == nil {
			failures = append(failures, errors.New("AWS mutation was confirmed but no exact Worker identity is publicly observable; preserving owned records for recovery"))
		}
	}
	if d.worker != nil && !d.workerAbsent {
		if d.destroyRequested {
			absent, err := d.aws.ResourcesAbsent(ctx, *d.worker)
			if err == nil && absent {
				d.workerAbsent = true
			} else if err != nil {
				failures = append(failures, err)
			} else {
				failures = append(failures, errors.New("exact AWS Worker resources remain after destroy"))
			}
		} else if err := d.revalidateAccount(ctx, d.worker.AccountID); err == nil {
			if err = d.aws.ObserveOwnedResources(ctx, *d.worker); err == nil {
				_, err = d.product.Call(ctx, "agent.workers.destroy", map[string]any{"identity": identityMap(*d.worker), "confirmation": "destroy_worker"})
				if err == nil {
					d.destroyRequested = true
					err = d.waitWorkerAbsent(ctx, *d.worker)
					if err == nil {
						var absent bool
						absent, err = d.aws.ResourcesAbsent(ctx, *d.worker)
						if err == nil && !absent {
							err = errors.New("exact AWS Worker resources remain after destroy")
						}
						if err == nil {
							d.workerAbsent = true
						}
					}
				}
			}
			if err != nil {
				failures = append(failures, err)
			}
		} else {
			failures = append(failures, err)
		}
	}
	if d.confirmedRunID == "" || d.workerAbsent {
		if err := d.cleanupRecords(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (d *driver) cleanupRecords(ctx context.Context) error {
	var failures []error
	if d.conversationID != "" {
		response, err := d.product.Call(ctx, "agent.chat.conversations.get", map[string]any{"conversation_id": d.conversationID, "message_limit": 1})
		if err == nil {
			revision := integer(object(response, "conversation")["revision"])
			if revision > 0 {
				_, err = d.product.Call(ctx, "agent.chat.conversations.delete", map[string]any{"conversation_id": d.conversationID, "expected_revision": revision, "idempotency_key": uuid4()})
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("delete owned conversation: %w", err))
		} else {
			d.conversationID = ""
		}
	}
	if d.createdCredential != nil {
		if d.confirmedRunID != "" && !d.workerAbsent {
			failures = append(failures, errors.New("refusing to delete owned credential before owned Worker absence"))
		} else {
			credential := *d.createdCredential
			err := d.revalidateAccount(ctx, credential.AccountID)
			if err == nil {
				_, err = d.product.Call(ctx, "agent.core.aws.credentials.delete", map[string]any{"credential_id": credential.CredentialID, "expected_revision": credential.Revision, "idempotency_key": uuid4()})
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("delete driver-created credential: %w", err))
			} else {
				d.createdCredential = nil
			}
		}
	}
	return errors.Join(failures...)
}

func (d *driver) revalidateAccount(ctx context.Context, expected string) error {
	identity, err := d.aws.Identity(ctx)
	if err != nil {
		return err
	}
	if identity.AccountID != expected {
		return fmt.Errorf("AWS account changed from %s to %s", expected, identity.AccountID)
	}
	return nil
}

func (d *driver) listCredentials(ctx context.Context) ([]credential, error) {
	response, err := d.product.Call(ctx, "agent.core.aws.credentials.list", map[string]any{"page_size": 100})
	if err != nil {
		return nil, err
	}
	values := objects(response["credentials"])
	result := make([]credential, 0, len(values))
	for _, value := range values {
		item, decodeErr := decodeCredential(value)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, item)
	}
	if stringValue(response, "next_page_token") != "" {
		return nil, errors.New("credential list unexpectedly exceeded one page")
	}
	return result, nil
}

func decodeCredential(value map[string]any) (credential, error) {
	result := credential{
		CredentialID: stringValue(value, "credential_id"), Region: stringValue(value, "region"),
		AccountID: stringValue(value, "account_id"), Revision: integer(value["revision"]),
		VerifiedRevision: integer(value["verified_revision"]), TestedAt: stringValue(value, "tested_at"),
	}
	if result.CredentialID == "" || result.Region == "" || (result.AccountID != "" && len(result.AccountID) != 12) || result.Revision < 1 || result.VerifiedRevision < 0 {
		return credential{}, errors.New("invalid credential projection")
	}
	return result, nil
}

func (d *driver) selectProfile(ctx context.Context) (profile, error) {
	response, err := d.product.Call(ctx, "agent.model_profiles.list", map[string]any{"page_size": 100})
	if err != nil {
		return profile{}, fmt.Errorf("list model profiles: %w", err)
	}
	targetProfileID := d.cfg.modelProfileID
	targetClientProfileID := ""
	if targetProfileID == "" {
		targetClientProfileID = stringValue(response, "default_conversation_client_profile_id")
	}
	for _, value := range objects(response["profiles"]) {
		item := profile{
			ProfileID: stringValue(value, "profile_id"), ClientProfileID: stringValue(value, "client_profile_id"), Provider: stringValue(value, "provider"),
			ModelKind: stringValue(value, "model_kind"), APIKeyConfigured: boolean(value["api_key_configured"]),
			Revision: integer(value["revision"]), CredentialVersion: integer(value["credential_version"]),
		}
		selected := targetProfileID != "" && item.ProfileID == targetProfileID ||
			targetProfileID == "" && item.ClientProfileID == targetClientProfileID
		if selected && item.Provider == "openai_compatible" && item.ModelKind == "conversation" && item.APIKeyConfigured && item.Revision > 0 && item.CredentialVersion > 0 {
			return item, nil
		}
	}
	return profile{}, errors.New("the selected conversation profile is not configured and ready")
}

func chatParams(selected profile, conversationID, message string) map[string]any {
	return map[string]any{
		"conversation_id": conversationID, "idempotency_key": uuid4(), "message": message,
		"model_profile_id": selected.ProfileID, "model_profile_revision": selected.Revision,
		"credential_version": selected.CredentialVersion,
	}
}

func firstWorkerPrompt(marker string) string {
	return "Deploy https://github.com/TencentCloud/TencentDB-Agent-Memory, record the deployment steps and the actual CPU, memory, and disk load of the machine that performs the work, then create a text artifact named acceptance.txt containing " + marker + ". Keep the execution environment available after the task so I can continue working in it."
}

func reuseWorkerPrompt() string {
	return "Continue in the execution environment retained from the previous task. Read its current UTC time and machine load, and return both values without creating a new environment."
}

func hasWorkersServer(response map[string]any) bool {
	core := object(response, "core")
	for _, value := range slice(core["capabilities"]) {
		if text, _ := value.(string); text == "workers.server" {
			return true
		}
	}
	return false
}

func (d *driver) planIDs(ctx context.Context) (map[string]struct{}, error) {
	plans, err := d.listPlans(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{}, len(plans))
	for _, current := range plans {
		result[current.PlanID] = struct{}{}
	}
	return result, nil
}

func (d *driver) listPlans(ctx context.Context) ([]plan, error) {
	response, err := d.product.Call(ctx, "agent.execution.v2.plans.list", map[string]any{"record_kind": "cloud_worker", "page_size": 200})
	if err != nil {
		return nil, fmt.Errorf("list Cloud Worker plans: %w", err)
	}
	if stringValue(response, "next_page_token") != "" {
		return nil, errors.New("Cloud Worker plan list exceeded one acceptance page")
	}
	values := objects(response["plans"])
	result := make([]plan, 0, len(values))
	for _, value := range values {
		item, decodeErr := decodePlan(value)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, item)
	}
	return result, nil
}

func decodePlan(value map[string]any) (plan, error) {
	quoteValue := object(value, "quote")
	result := plan{
		PlanID: stringValue(value, "plan_id"), ExecutionID: stringValue(value, "execution_id"),
		ConfirmationID: stringValue(value, "confirmation_id"), ConversationID: stringValue(value, "conversation_id"),
		Status: stringValue(value, "status"), Revision: integer(value["revision"]),
		Quote: quote{AmountMicros: integer(quoteValue["amount_micros"]), Currency: stringValue(quoteValue, "currency"),
			Digest: stringValue(quoteValue, "digest"), SourceTime: stringValue(quoteValue, "source_time"), ExpiresAt: stringValue(quoteValue, "expires_at")},
	}
	if result.PlanID == "" || result.ExecutionID == "" || result.ConfirmationID == "" || result.ConversationID == "" || result.Revision < 1 {
		return plan{}, errors.New("invalid Cloud Worker plan projection")
	}
	return result, nil
}

func (d *driver) findNewPlan(ctx context.Context, baseline map[string]struct{}, conversationID, executionID string) (plan, error) {
	deadline := time.Now().Add(d.cfg.timeout)
	for time.Now().Before(deadline) {
		plans, err := d.listPlans(ctx)
		if err != nil {
			return plan{}, err
		}
		var candidates []plan
		for _, current := range plans {
			_, old := baseline[current.PlanID]
			if !old && current.ConversationID == conversationID && (executionID == "" || current.ExecutionID == executionID) {
				candidates = append(candidates, current)
			}
		}
		if len(candidates) == 1 {
			return candidates[0], nil
		}
		if len(candidates) > 1 {
			return plan{}, fmt.Errorf("multiple new plans appeared for one acceptance turn: %d", len(candidates))
		}
		if err := waitPoll(ctx, d.cfg.poll); err != nil {
			return plan{}, err
		}
	}
	return plan{}, errors.New("timed out waiting for the current turn's new plan")
}

func validPricedQuote(value quote) bool {
	if value.AmountMicros <= 0 || value.Currency != "USD" || len(value.Digest) != 64 {
		return false
	}
	source, sourceErr := time.Parse(time.RFC3339Nano, value.SourceTime)
	expires, expiresErr := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	return sourceErr == nil && expiresErr == nil && expires.After(source)
}

func (d *driver) listConfirmations(ctx context.Context, executionID string, states []string) ([]map[string]any, error) {
	response, err := d.product.Call(ctx, "agent.core.confirmations.list", map[string]any{
		"operation_domain": "cloud_worker.execute", "target_id": executionID, "states": states, "page_size": 100,
	})
	if err != nil {
		return nil, err
	}
	if stringValue(response, "next_page_token") != "" {
		return nil, errors.New("confirmation list exceeded one acceptance page")
	}
	return objects(response["confirmations"]), nil
}

func (d *driver) pendingConfirmation(ctx context.Context, current plan) (map[string]any, error) {
	values, err := d.listConfirmations(ctx, current.ExecutionID, []string{"pending"})
	if err != nil {
		return nil, err
	}
	if len(values) != 1 || stringValue(values[0], "confirmation_id") != current.ConfirmationID || stringValue(values[0], "state") != "pending" || integer(values[0]["revision"]) < 1 {
		return nil, errors.New("pending confirmation does not match the exact current plan")
	}
	binding := object(values[0], "binding")
	if stringValue(binding, "operation_domain") != "cloud_worker.execute" || stringValue(binding, "execution_id") != current.ExecutionID || stringValue(binding, "plan_id") != current.PlanID || integer(binding["plan_revision"]) != current.Revision {
		return nil, errors.New("pending confirmation binding does not match the exact current plan")
	}
	return values[0], nil
}

func (d *driver) getRun(ctx context.Context, id string) (run, error) {
	response, err := d.product.Call(ctx, "agent.execution.v2.runs.get", map[string]any{"record_kind": "cloud_worker", "run_id": id})
	if err != nil {
		return run{}, err
	}
	value := object(response, "run")
	result := run{
		RunID: stringValue(value, "run_id"), PlanID: stringValue(value, "plan_id"), ConversationID: stringValue(value, "conversation_id"),
		Status: stringValue(value, "status"), WorkerID: stringValue(value, "worker_id"),
		FailureCode: stringValue(value, "failure_code"), FailureSummary: stringValue(value, "failure_summary"),
		PersistentWorker: boolean(value["persistent_worker"]), ArtifactIDs: stringsValue(value["artifact_ids"]),
	}
	if result.RunID != id {
		return run{}, errors.New("run readback identity mismatch")
	}
	return result, nil
}

func (d *driver) waitRun(ctx context.Context, id string) (run, error) {
	for {
		current, err := d.getRun(ctx, id)
		if err != nil {
			return run{}, fmt.Errorf("read current run %s: %w", id, err)
		}
		switch current.Status {
		case "succeeded":
			return current, nil
		case "failed", "canceled", "rejected", "expired":
			return run{}, fmt.Errorf("Worker run %s ended %s: %s: %s", id, current.Status, current.FailureCode, current.FailureSummary)
		}
		if err := waitPoll(ctx, d.cfg.poll); err != nil {
			return run{}, err
		}
	}
}

func (d *driver) listWorkers(ctx context.Context) ([]workerStatus, error) {
	response, err := d.product.Call(ctx, "agent.workers.list", map[string]any{})
	if err != nil {
		return nil, err
	}
	values := objects(response["workers"])
	result := make([]workerStatus, 0, len(values))
	for _, value := range values {
		item, decodeErr := decodeWorker(value)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, item)
	}
	return result, nil
}

func decodeWorker(value map[string]any) (workerStatus, error) {
	identity := object(value, "identity")
	result := workerStatus{
		Identity: workerIdentity{
			WorkerID: stringValue(identity, "worker_id"), InstanceID: stringValue(identity, "instance_id"),
			KeyPairID: stringValue(identity, "key_pair_id"), SecurityGroupID: stringValue(identity, "security_group_id"),
			CredentialID: stringValue(identity, "credential_id"), CredentialRevision: integer(identity["credential_revision"]),
			AccountID: stringValue(identity, "account_id"), Region: stringValue(identity, "region"),
		},
		Availability: stringValue(value, "availability"), EC2State: stringValue(value, "ec2_state"),
		WorkerPhase: stringValue(value, "worker_phase"), PublicIPv4: stringValue(value, "public_ipv4"), Server: object(value, "server"),
	}
	if result.Identity.WorkerID == "" || result.Identity.InstanceID == "" || result.Identity.KeyPairID == "" || result.Identity.SecurityGroupID == "" ||
		result.Identity.CredentialID == "" || result.Identity.CredentialRevision < 1 || len(result.Identity.AccountID) != 12 || result.Identity.Region == "" {
		return workerStatus{}, errors.New("invalid Worker identity projection")
	}
	return result, nil
}

func (d *driver) waitWorker(ctx context.Context, id string) (workerStatus, error) {
	for {
		workers, err := d.listWorkers(ctx)
		if err != nil {
			return workerStatus{}, err
		}
		for _, current := range workers {
			if current.Identity.WorkerID != id {
				continue
			}
			if current.Availability == "available" && current.EC2State == "running" && current.WorkerPhase == "idle" && current.PublicIPv4 != "" && validLoad(current.Server) {
				return current, nil
			}
		}
		if err := waitPoll(ctx, d.cfg.poll); err != nil {
			return workerStatus{}, err
		}
	}
}

func validLoad(server map[string]any) bool {
	if stringValue(server, "last_seen") == "" {
		return false
	}
	for _, key := range []string{"load_1", "load_5", "load_15"} {
		if _, ok := number(server[key]); !ok {
			return false
		}
	}
	return true
}

func (d *driver) waitWorkerAbsent(ctx context.Context, identity workerIdentity) error {
	for {
		workers, err := d.listWorkers(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, current := range workers {
			if current.Identity == identity {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if err := waitPoll(ctx, d.cfg.poll); err != nil {
			return err
		}
	}
}

func (d *driver) downloadMarkedArtifact(ctx context.Context, current run, marker string) (string, string, error) {
	for _, artifactID := range current.ArtifactIDs {
		response, err := d.product.Call(ctx, "agent.execution.v2.artifacts.get", map[string]any{"record_kind": "cloud_worker", "artifact_id": artifactID})
		if err != nil {
			return "", "", err
		}
		artifact := object(response, "artifact")
		if stringValue(artifact, "artifact_id") != artifactID || stringValue(artifact, "execution_id") != current.RunID || stringValue(artifact, "status") != "verified" {
			return "", "", errors.New("artifact projection identity/status mismatch")
		}
		expectedSize := integer(artifact["size_bytes"])
		expectedSHA := stringValue(artifact, "sha256")
		body, downloadErr := d.downloadArtifact(ctx, artifactID, expectedSize, expectedSHA)
		if downloadErr != nil {
			return "", "", downloadErr
		}
		if bytes.Contains(body, []byte(marker)) {
			path := filepath.Join(d.cfg.runDir, "real-worker-artifact-"+artifactID+".bin")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				return "", "", err
			}
			return artifactID, expectedSHA, nil
		}
	}
	return "", "", errors.New("no downloaded artifact contained the current acceptance marker")
}

func (d *driver) downloadArtifact(ctx context.Context, artifactID string, expectedSize int64, expectedSHA string) ([]byte, error) {
	if expectedSize <= 0 || expectedSize > 8<<20 || len(expectedSHA) != 64 {
		return nil, errors.New("artifact metadata is outside the acceptance bounds")
	}
	var result []byte
	for offset := int64(0); ; {
		response, err := d.product.Call(ctx, "agent.execution.v2.artifacts.download", map[string]any{
			"record_kind": "cloud_worker", "artifact_id": artifactID, "offset_bytes": offset, "max_chunk_bytes": 512 << 10,
		})
		if err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.Strict().DecodeString(stringValue(response, "data_base64"))
		if err != nil || len(data) == 0 {
			return nil, errors.New("artifact chunk is not canonical base64")
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != stringValue(response, "chunk_sha256") || stringValue(response, "artifact_sha256") != expectedSHA ||
			integer(response["offset_bytes"]) != offset || integer(response["size_bytes"]) != expectedSize || integer(response["next_offset_bytes"]) != offset+int64(len(data)) {
			return nil, errors.New("artifact chunk digest or range mismatch")
		}
		result = append(result, data...)
		offset += int64(len(data))
		eof := boolean(response["eof"])
		if eof != (offset == expectedSize) {
			return nil, errors.New("artifact EOF does not match its declared size")
		}
		if eof {
			break
		}
	}
	digest := sha256.Sum256(result)
	if int64(len(result)) != expectedSize || hex.EncodeToString(digest[:]) != expectedSHA {
		return nil, errors.New("complete artifact size or digest mismatch")
	}
	return result, nil
}

func (d *driver) waitTurn(ctx context.Context, turnID string) error {
	for {
		response, err := d.product.Call(ctx, "agent.chat.turns.list", map[string]any{"conversation_id": d.conversationID, "limit": 100})
		if err != nil {
			return err
		}
		for _, current := range objects(response["turns"]) {
			if stringValue(current, "turn_id") != turnID {
				continue
			}
			switch stringValue(current, "state") {
			case "completed":
				return nil
			case "failed", "canceled":
				return fmt.Errorf("durable turn ended %s: %s: %s", stringValue(current, "state"), stringValue(current, "terminal_code"), stringValue(current, "terminal_summary"))
			}
		}
		if err := waitPoll(ctx, d.cfg.poll); err != nil {
			return err
		}
	}
}

func identityMap(identity workerIdentity) map[string]any {
	return map[string]any{
		"worker_id": identity.WorkerID, "instance_id": identity.InstanceID, "key_pair_id": identity.KeyPairID,
		"security_group_id": identity.SecurityGroupID, "credential_id": identity.CredentialID,
		"credential_revision": identity.CredentialRevision, "account_id": identity.AccountID, "region": identity.Region,
	}
}

type httpProduct struct {
	base, token string
	client      *http.Client
}

func newHTTPProduct(base, token string, timeout time.Duration) (*httpProduct, error) {
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.TrimSpace(token) == "" {
		return nil, errors.New("invalid Message Server HTTP configuration")
	}
	return &httpProduct{base: strings.TrimRight(base, "/"), token: token, client: &http.Client{Timeout: minDuration(timeout, 2*time.Minute)}}, nil
}

func (client *httpProduct) Call(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	body, err := json.Marshal(map[string]any{"action": action, "params": params})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base+"/_p2p/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8<<20))
	decoder.UseNumber()
	var result map[string]any
	if err = decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("%s returned HTTP %d with invalid JSON", action, response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := stringValue(result, "error")
		if message == "" {
			message = stringValue(result, "message")
		}
		return nil, fmt.Errorf("%s returned HTTP %d: %s", action, response.StatusCode, message)
	}
	return result, nil
}

func (client *httpProduct) StartTurn(ctx context.Context, params map[string]any, stopAtConfirmation bool) (streamResult, error) {
	result, after, err := client.createTurn(ctx, params)
	if err != nil {
		return streamResult{}, err
	}
	conversationID := stringValue(params, "conversation_id")
	for attempt := 0; attempt < 5; attempt++ {
		terminal, next, err := client.readTurn(ctx, conversationID, stopAtConfirmation, after, &result)
		if next > after {
			after = next
		}
		if terminal {
			return result, err
		}
		if err == nil || ctx.Err() != nil || attempt == 4 {
			return result, err
		}
		if err = waitPoll(ctx, time.Second); err != nil {
			return result, err
		}
	}
	return result, errors.New("durable stream reconnect attempts exhausted")
}

func (client *httpProduct) createTurn(ctx context.Context, params map[string]any) (streamResult, int64, error) {
	conversationID := stringValue(params, "conversation_id")
	body, err := json.Marshal(params)
	if err != nil {
		return streamResult{}, 0, err
	}
	endpoint := client.base + "/_p2p/agent/chat/conversations/" + url.PathEscape(conversationID) + "/turns"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return streamResult{}, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return streamResult{}, 0, fmt.Errorf("create durable turn completion is unknown: %w", err)
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8<<20))
	decoder.UseNumber()
	var receipt map[string]any
	if err = decoder.Decode(&receipt); err != nil {
		return streamResult{}, 0, fmt.Errorf("create durable turn returned HTTP %d with invalid JSON", response.StatusCode)
	}
	if response.StatusCode != http.StatusAccepted {
		return streamResult{}, 0, fmt.Errorf("create durable turn returned HTTP %d: %s", response.StatusCode, stringValue(receipt, "error"))
	}
	result := streamResult{TurnID: stringValue(receipt, "turn_id")}
	seq := integer(receipt["seq"])
	if conversationID == "" || result.TurnID == "" || stringValue(receipt, "conversation_id") != conversationID || seq <= 0 {
		return streamResult{}, 0, errors.New("create durable turn returned an invalid receipt")
	}
	return result, seq, nil
}

func (client *httpProduct) readTurn(ctx context.Context, conversationID string, stopAtConfirmation bool, after int64, result *streamResult) (bool, int64, error) {
	endpoint := client.base + "/_p2p/agent/chat/conversations/" + url.PathEscape(conversationID) + "/turns/" + url.PathEscape(result.TurnID) + "/events"
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false, after, err
	}
	query := parsed.Query()
	query.Set("after_seq", strconv.FormatInt(after, 10))
	parsed.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return false, after, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", strconv.FormatInt(after, 10))
	streamClient := *client.client
	streamClient.Timeout = 0
	response, err := streamClient.Do(request)
	if err != nil {
		return false, after, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, after, fmt.Errorf("watch durable turn returned HTTP %d", response.StatusCode)
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		return false, after, errors.New("watch durable turn returned a non-SSE response")
	}

	maxSeq := after
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var eventID, eventName string
	dataLines := make([]string, 0, 1)
	apply := func() (bool, error) {
		if len(dataLines) == 0 {
			eventID, eventName = "", ""
			return false, nil
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(strings.Join(dataLines, "\n")), &frame); err != nil {
			return false, errors.New("watch durable turn returned invalid SSE JSON")
		}
		if stringValue(frame, "event") == "" {
			frame["event"] = eventName
		}
		wireSeq, parseErr := strconv.ParseInt(eventID, 10, 64)
		seq := integer(frame["seq"])
		if parseErr != nil || wireSeq <= 0 || seq != wireSeq {
			return false, errors.New("watch durable turn returned an invalid SSE cursor")
		}
		if seq > maxSeq {
			maxSeq = seq
		}
		return applyStreamFrame(result, frame, stopAtConfirmation)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			terminal, frameErr := apply()
			eventID, eventName, dataLines = "", "", dataLines[:0]
			if frameErr != nil || terminal {
				return terminal, maxSeq, frameErr
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if found {
			value = strings.TrimPrefix(value, " ")
		}
		switch name {
		case "id":
			eventID = value
		case "event":
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	if err = scanner.Err(); err != nil {
		return false, maxSeq, err
	}
	return false, maxSeq, io.ErrUnexpectedEOF
}

func applyStreamFrame(result *streamResult, frame map[string]any, stopAtConfirmation bool) (bool, error) {
	if turnID := stringValue(frame, "turn_id"); turnID != "" {
		if result.TurnID != "" && result.TurnID != turnID {
			return false, errors.New("durable stream turn identity changed")
		}
		result.TurnID = turnID
	}
	event := stringValue(frame, "event")
	switch event {
	case "error", "cancelled":
		data := object(frame, "data")
		return true, fmt.Errorf("durable turn ended %s: %s: %s", event, stringValue(data, "error_code"), stringValue(data, "error_summary"))
	case "waiting_confirmation":
		data := object(frame, "data")
		result.ConfirmationID = stringValue(data, "confirmation_id")
		result.ExecutionID = stringValue(data, "execution_id")
		if result.TurnID == "" || result.ConfirmationID == "" || result.ExecutionID == "" || !stopAtConfirmation {
			return false, errors.New("unexpected or incomplete waiting_confirmation event")
		}
		return true, nil
	case "done":
		if stopAtConfirmation || result.TurnID == "" {
			return true, errors.New("durable stream completed without the expected Worker offer")
		}
		result.Done = true
		return true, nil
	default:
		return false, nil
	}
}

type cliAWS struct{ profile, region string }

func (client *cliAWS) Identity(ctx context.Context) (cloudIdentity, error) {
	var value struct {
		Account string `json:"Account"`
		ARN     string `json:"Arn"`
	}
	if err := client.json(ctx, &value, "sts", "get-caller-identity"); err != nil {
		return cloudIdentity{}, err
	}
	if len(value.Account) != 12 || value.ARN == "" {
		return cloudIdentity{}, errors.New("AWS caller identity is incomplete")
	}
	return cloudIdentity{AccountID: value.Account, ARN: value.ARN}, nil
}

func (client *cliAWS) ExportCredential(ctx context.Context) (exportedCredential, error) {
	command := exec.CommandContext(ctx, "aws", "configure", "export-credentials", "--profile", client.profile, "--format", "process")
	command.Env = append(os.Environ(), "AWS_PAGER=")
	var stdout bytes.Buffer
	command.Stdout, command.Stderr = &stdout, io.Discard
	if err := command.Run(); err != nil {
		return exportedCredential{}, errors.New("AWS CLI could not resolve the explicit profile credentials")
	}
	var value struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
	}
	if json.Unmarshal(stdout.Bytes(), &value) != nil || value.AccessKeyID == "" || value.SecretAccessKey == "" {
		return exportedCredential{}, errors.New("AWS CLI returned an incomplete credential process document")
	}
	return exportedCredential{AccessKeyID: value.AccessKeyID, SecretAccessKey: value.SecretAccessKey, SessionToken: value.SessionToken}, nil
}

func (client *cliAWS) ObserveOwnedResources(ctx context.Context, identity workerIdentity) error {
	if err := validateWorkerIDs(identity); err != nil {
		return err
	}
	if err := client.requireAccount(ctx, identity.AccountID); err != nil {
		return err
	}
	instance, err := client.describeInstance(ctx, identity.InstanceID)
	if err != nil || stringValue(instance, "InstanceId") != identity.InstanceID || stringValue(object(instance, "State"), "Name") == "terminated" || !ownedTags(instance["Tags"], identity.WorkerID) {
		return errors.Join(errors.New("exact EC2 instance ownership readback failed"), err)
	}
	if err = client.requireAccount(ctx, identity.AccountID); err != nil {
		return err
	}
	key, err := client.describeKey(ctx, identity.KeyPairID)
	if err != nil || stringValue(key, "KeyPairId") != identity.KeyPairID || !ownedTags(key["Tags"], identity.WorkerID) {
		return errors.Join(errors.New("exact EC2 key pair ownership readback failed"), err)
	}
	if err = client.requireAccount(ctx, identity.AccountID); err != nil {
		return err
	}
	group, err := client.describeGroup(ctx, identity.SecurityGroupID)
	if err != nil || stringValue(group, "GroupId") != identity.SecurityGroupID || !ownedTags(group["Tags"], identity.WorkerID) {
		return errors.Join(errors.New("exact EC2 security group ownership readback failed"), err)
	}
	return nil
}

func (client *cliAWS) ResourcesAbsent(ctx context.Context, identity workerIdentity) (bool, error) {
	if err := validateWorkerIDs(identity); err != nil {
		return false, err
	}
	for {
		if err := client.requireAccount(ctx, identity.AccountID); err != nil {
			return false, err
		}
		instance, instanceErr := client.describeInstance(ctx, identity.InstanceID)
		instanceAbsent := awsNotFound(instanceErr) || (instanceErr == nil && stringValue(object(instance, "State"), "Name") == "terminated")
		if instanceErr != nil && !awsNotFound(instanceErr) {
			return false, instanceErr
		}
		if err := client.requireAccount(ctx, identity.AccountID); err != nil {
			return false, err
		}
		_, keyErr := client.describeKey(ctx, identity.KeyPairID)
		keyAbsent := awsNotFound(keyErr)
		if keyErr != nil && !keyAbsent {
			return false, keyErr
		}
		if err := client.requireAccount(ctx, identity.AccountID); err != nil {
			return false, err
		}
		_, groupErr := client.describeGroup(ctx, identity.SecurityGroupID)
		groupAbsent := awsNotFound(groupErr)
		if groupErr != nil && !groupAbsent {
			return false, groupErr
		}
		if instanceAbsent && keyAbsent && groupAbsent {
			return true, nil
		}
		if err := waitPoll(ctx, 5*time.Second); err != nil {
			return false, err
		}
	}
}

func (client *cliAWS) requireAccount(ctx context.Context, expected string) error {
	identity, err := client.Identity(ctx)
	if err != nil {
		return err
	}
	if identity.AccountID != expected {
		return fmt.Errorf("AWS account changed from %s to %s", expected, identity.AccountID)
	}
	return nil
}

func (client *cliAWS) describeInstance(ctx context.Context, id string) (map[string]any, error) {
	var value map[string]any
	if err := client.json(ctx, &value, "ec2", "describe-instances", "--instance-ids", id); err != nil {
		return nil, err
	}
	reservations := objects(value["Reservations"])
	if len(reservations) != 1 {
		return nil, errors.New("exact EC2 instance readback cardinality mismatch")
	}
	instances := objects(reservations[0]["Instances"])
	if len(instances) != 1 {
		return nil, errors.New("exact EC2 instance readback cardinality mismatch")
	}
	return instances[0], nil
}

func (client *cliAWS) describeKey(ctx context.Context, id string) (map[string]any, error) {
	var value map[string]any
	if err := client.json(ctx, &value, "ec2", "describe-key-pairs", "--key-pair-ids", id); err != nil {
		return nil, err
	}
	items := objects(value["KeyPairs"])
	if len(items) != 1 {
		return nil, errors.New("exact key pair readback cardinality mismatch")
	}
	return items[0], nil
}

func (client *cliAWS) describeGroup(ctx context.Context, id string) (map[string]any, error) {
	var value map[string]any
	if err := client.json(ctx, &value, "ec2", "describe-security-groups", "--group-ids", id); err != nil {
		return nil, err
	}
	items := objects(value["SecurityGroups"])
	if len(items) != 1 {
		return nil, errors.New("exact security group readback cardinality mismatch")
	}
	return items[0], nil
}

type awsCLIError struct{ text string }

func (err awsCLIError) Error() string { return "AWS CLI request failed: " + err.text }

func (client *cliAWS) json(ctx context.Context, target any, args ...string) error {
	arguments := append(append([]string{}, args...), "--profile", client.profile, "--region", client.region, "--output", "json", "--no-cli-pager")
	command := exec.CommandContext(ctx, "aws", arguments...)
	command.Env = append(os.Environ(), "AWS_PAGER=")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		text := strings.TrimSpace(stderr.String())
		if len(text) > 500 {
			text = text[:500]
		}
		return awsCLIError{text: text}
	}
	decoder := json.NewDecoder(&stdout)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errors.New("AWS CLI returned invalid JSON")
	}
	return nil
}

func awsNotFound(err error) bool {
	var cliErr awsCLIError
	if !errors.As(err, &cliErr) {
		return false
	}
	for _, code := range []string{"InvalidInstanceID.NotFound", "InvalidKeyPair.NotFound", "InvalidGroup.NotFound"} {
		if strings.Contains(cliErr.text, code) {
			return true
		}
	}
	return false
}

func ownedTags(value any, workerID string) bool {
	tags := map[string]string{}
	for _, current := range objects(value) {
		tags[stringValue(current, "Key")] = stringValue(current, "Value")
	}
	return tags["dirextalk:managed-by"] == "sshworker" && tags["dirextalk:worker"] == workerID
}

func validateWorkerIDs(identity workerIdentity) error {
	if identity.WorkerID == "" || !strings.HasPrefix(identity.InstanceID, "i-") || strings.TrimSpace(identity.KeyPairID) == "" ||
		!strings.HasPrefix(identity.SecurityGroupID, "sg-") || len(identity.AccountID) != 12 || identity.Region == "" {
		return errors.New("invalid exact Worker AWS identity")
	}
	return nil
}

func writeReceiptAtomic(path string, value receipt) error {
	if value.Schema != receiptSchema ||
		(!value.Credential.CreatedByDriver && !value.Credential.PreexistingVerified) ||
		!value.Credential.Tested || !value.Credential.Listed || !value.Catalog.WorkersServer ||
		!value.Quote.Observed || !value.Confirmation.Confirmed || !value.Worker.Created ||
		!value.Worker.StatusObserved || !value.Worker.LoadObserved || !value.Artifact.Downloaded ||
		!value.Reuse.Completed || !value.Reuse.NoNewCreationConfirmation ||
		!value.Destroy.Completed || !value.Destroy.ResourcesAbsent || value.S3Used {
		return errors.New("refusing to write incomplete receipt")
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp-" + marker()
	if err = os.WriteFile(temporary, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func uuid4() string {
	body, err := os.ReadFile("/proc/sys/kernel/random/uuid")
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(body))
}

func marker() string { return fmt.Sprintf("%d", time.Now().UTC().UnixNano()) }

func waitPoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func object(value map[string]any, key string) map[string]any {
	if result, ok := value[key].(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func objects(value any) []map[string]any {
	items := slice(value)
	result := make([]map[string]any, 0, len(items))
	for _, current := range items {
		if item, ok := current.(map[string]any); ok {
			result = append(result, item)
		}
	}
	return result
}

func slice(value any) []any {
	result, _ := value.([]any)
	return result
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func stringsValue(value any) []string {
	items := slice(value)
	result := make([]string, 0, len(items))
	for _, current := range items {
		if text, ok := current.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func integer(value any) int64 {
	switch value := value.(type) {
	case json.Number:
		result, _ := value.Int64()
		return result
	case float64:
		return int64(value)
	case int:
		return int64(value)
	case int64:
		return value
	default:
		return 0
	}
}

func number(value any) (float64, bool) {
	switch value := value.(type) {
	case json.Number:
		result, err := value.Float64()
		return result, err == nil
	case float64:
		return value, true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}

func boolean(value any) bool {
	result, _ := value.(bool)
	return result
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value)+1)
	for key, current := range value {
		result[key] = current
	}
	return result
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "real Worker acceptance:", err)
	os.Exit(1)
}
