package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	awsAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	awsRegionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	awsImagePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$`)
)

type AWSCredentialStore struct{ store *Store }

var _ awsfoundation.CredentialStore = (*AWSCredentialStore)(nil)

func (store *Store) AWSCredentialStore() *AWSCredentialStore {
	return &AWSCredentialStore{store: store}
}

func (adapter *AWSCredentialStore) Get(ctx context.Context, agentInstanceID string) (awsfoundation.EncryptedSourceCredential, error) {
	if adapter == nil || adapter.store == nil {
		return awsfoundation.EncryptedSourceCredential{}, awsfoundation.ErrCredentialEnvelope
	}
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed != adapter.store.instanceID {
		return awsfoundation.EncryptedSourceCredential{}, awsfoundation.ErrCredentialNotFound
	}
	var value awsfoundation.EncryptedSourceCredential
	if err := adapter.store.pool.QueryRow(ctx, `
		SELECT schema_version, agent_instance_id, account_id, region, operation_id, generation, created_at, nonce, ciphertext
		FROM aws_source_credentials WHERE agent_instance_id=$1`, parsed).Scan(
		&value.SchemaVersion, &value.AgentInstanceID, &value.AccountID, &value.Region, &value.OperationID, &value.Generation,
		&value.CreatedAt, &value.Nonce, &value.Ciphertext,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return awsfoundation.EncryptedSourceCredential{}, awsfoundation.ErrCredentialNotFound
		}
		return awsfoundation.EncryptedSourceCredential{}, awsfoundation.ErrCredentialEnvelope
	}
	value.CreatedAt = value.CreatedAt.UTC()
	if err := validateEncryptedSourceCredential(value); err != nil {
		return awsfoundation.EncryptedSourceCredential{}, err
	}
	return value, nil
}

func (adapter *AWSCredentialStore) PutCAS(ctx context.Context, agentInstanceID string, expectedGeneration uint64, value awsfoundation.EncryptedSourceCredential) error {
	if adapter == nil || adapter.store == nil || agentInstanceID != value.AgentInstanceID || value.Generation != expectedGeneration+1 {
		return awsfoundation.ErrCredentialEnvelope
	}
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed != adapter.store.instanceID || validateEncryptedSourceCredential(value) != nil {
		return awsfoundation.ErrCredentialEnvelope
	}
	if expectedGeneration == 0 {
		result, err := adapter.store.pool.Exec(ctx, `
			INSERT INTO aws_source_credentials
			    (agent_instance_id, account_id, region, operation_id, generation, schema_version, nonce, ciphertext, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (agent_instance_id) DO NOTHING`, parsed, value.AccountID, value.Region, value.OperationID,
			value.Generation, value.SchemaVersion, value.Nonce, value.Ciphertext, value.CreatedAt.UTC())
		if err != nil {
			return awsfoundation.ErrCredentialEnvelope
		}
		if result.RowsAffected() != 1 {
			return awsfoundation.ErrCredentialRevisionConflict
		}
		return nil
	}
	result, err := adapter.store.pool.Exec(ctx, `
		UPDATE aws_source_credentials
		SET account_id=$3, region=$4, operation_id=$5, generation=$6, schema_version=$7, nonce=$8, ciphertext=$9,
		    created_at=$10, updated_at=clock_timestamp()
		WHERE agent_instance_id=$1 AND generation=$2`, parsed, expectedGeneration, value.AccountID, value.Region,
		value.OperationID, value.Generation, value.SchemaVersion, value.Nonce, value.Ciphertext, value.CreatedAt.UTC())
	if err != nil {
		return awsfoundation.ErrCredentialEnvelope
	}
	if result.RowsAffected() != 1 {
		return awsfoundation.ErrCredentialRevisionConflict
	}
	return nil
}

func (adapter *AWSCredentialStore) DeleteCAS(ctx context.Context, agentInstanceID string, expectedGeneration uint64) error {
	if adapter == nil || adapter.store == nil || expectedGeneration == 0 {
		return awsfoundation.ErrCredentialRevisionConflict
	}
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed != adapter.store.instanceID {
		return awsfoundation.ErrCredentialNotFound
	}
	result, err := adapter.store.pool.Exec(ctx, `DELETE FROM aws_source_credentials WHERE agent_instance_id=$1 AND generation=$2`, parsed, expectedGeneration)
	if err != nil {
		return awsfoundation.ErrCredentialEnvelope
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := adapter.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM aws_source_credentials WHERE agent_instance_id=$1)`, parsed).Scan(&exists); err != nil {
		return awsfoundation.ErrCredentialEnvelope
	}
	if !exists {
		return awsfoundation.ErrCredentialNotFound
	}
	return awsfoundation.ErrCredentialRevisionConflict
}

func validateEncryptedSourceCredential(value awsfoundation.EncryptedSourceCredential) error {
	parsed, err := uuid.Parse(value.AgentInstanceID)
	operationID, operationErr := uuid.Parse(value.OperationID)
	if err != nil || parsed == uuid.Nil || !awsAccountPattern.MatchString(value.AccountID) || !awsRegionPattern.MatchString(value.Region) ||
		operationErr != nil || operationID == uuid.Nil ||
		value.Generation == 0 || value.SchemaVersion != "dirextalk.agent.aws-source-credential/aes256gcm/v1" ||
		value.CreatedAt.IsZero() || len(value.Nonce) != 12 || len(value.Ciphertext) < 17 {
		return awsfoundation.ErrCredentialEnvelope
	}
	return nil
}
