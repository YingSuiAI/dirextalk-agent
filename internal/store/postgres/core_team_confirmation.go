package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/jackc/pgx/v5"
)

const teamCredentialMutationLockName = "dirextalk:team-credential-mutation"

func validateTeamBinding(plan coreteam.Plan, binding coreconfirmation.Binding) (coreconfirmation.Binding, error) {
	expected, err := coreteam.ConfirmationBinding(plan)
	if err != nil {
		return coreconfirmation.Binding{}, coreteam.ErrInvalid
	}
	normalized, err := binding.Normalize()
	if err != nil || !normalized.Equal(expected) {
		return coreconfirmation.Binding{}, coreteam.ErrInvalid
	}
	return normalized, nil
}

func lockTeamCredentialMutation(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	if ctx == nil || tx == nil || scope.Validate() != nil {
		return coreteam.ErrInvalid
	}
	lock := fmt.Sprintf("%s:%d:%s", teamCredentialMutationLockName, scope.AccountGeneration, scope.OwnerID)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lock)
	return err
}

func tryLockTeamCredentialMutationForTask(ctx context.Context, tx pgx.Tx, taskID string) (bool, error) {
	if ctx == nil || tx == nil || !coretask.ValidUUID(taskID) {
		return false, coretask.ErrInvalid
	}
	var scope coreteam.Scope
	err := tx.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_team_executions WHERE task_id=$1`, taskID).Scan(&scope.OwnerID, &scope.AccountGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	lock := fmt.Sprintf("%s:%d:%s", teamCredentialMutationLockName, scope.AccountGeneration, scope.OwnerID)
	var acquired bool
	err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, lock).Scan(&acquired)
	return acquired, err
}

func lockTeamCredentialMutationForTask(ctx context.Context, tx pgx.Tx, taskID string) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(taskID) {
		return coretask.ErrInvalid
	}
	var scope coreteam.Scope
	err := tx.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_team_executions WHERE task_id=$1`, taskID).Scan(&scope.OwnerID, &scope.AccountGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return lockTeamCredentialMutation(ctx, tx, scope)
}

func lockTeamCredentialMutationForConfirmation(ctx context.Context, tx pgx.Tx, confirmationID string) error {
	if ctx == nil || tx == nil || !coretask.ValidUUID(confirmationID) {
		return coretask.ErrInvalid
	}
	var scope coreteam.Scope
	err := tx.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_team_executions WHERE confirmation_id=$1`, confirmationID).Scan(&scope.OwnerID, &scope.AccountGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return lockTeamCredentialMutation(ctx, tx, scope)
}

func requireNoActiveTeamExecutionTx(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM core_team_executions
		WHERE owner_id=$1 AND account_generation=$2
		  AND (status IN ('queued','running','cleaning_up') OR cleanup_verified_at IS NULL)
	)`, scope.OwnerID, scope.AccountGeneration).Scan(&active); err != nil {
		return err
	}
	if active {
		return coreteam.ErrExecutionActive
	}
	return nil
}

func requireTeamCredentialRevision(ctx context.Context, tx pgx.Tx, plan coreteam.Plan) error {
	var revision int64
	err := tx.QueryRow(ctx, `SELECT revision FROM core_aws_credentials WHERE credential_id=$1 AND owner_id=$2 AND account_generation=$3 FOR UPDATE`, plan.CredentialID, plan.OwnerID, plan.AccountGeneration).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && revision != int64(plan.CredentialRevision)) {
		return coreteam.ErrConflict
	}
	return err
}

func (s *CoreTeamStore) RequireNoActiveTeamExecution(ctx context.Context, scope coreteam.Scope) error {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil {
		return coreteam.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamAdmission(ctx, tx, scope); err != nil {
		return err
	}
	if err = lockTeamCredentialMutation(ctx, tx, scope); err != nil {
		return err
	}
	if err = requireNoActiveTeamExecutionTx(ctx, tx, scope); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var _ coreteam.ActiveExecutionGuard = (*CoreTeamStore)(nil)

func (s *CoreAWSStore) CreateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential coreaws.Credentials) (coreaws.Credentials, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || credential.Validate() != nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(credential)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreaws.Credentials{}, err
	}
	defer tx.Rollback(ctx)
	if err = requireGuardedCredentialMutation(ctx, tx, scope); err != nil {
		return coreaws.Credentials{}, err
	}
	configured := credentialSessionConfigured(credential)
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,owner_id,account_generation,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, credential.ID, scope.OwnerID, scope.AccountGeneration, credential.Name, credential.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, credential.AccountID, credential.UserARN, credential.VerifiedRevision, credential.Revision, nullableCredentialTime(credential.TestedAt), credential.CreatedAt, credential.UpdatedAt); err != nil {
		return coreaws.Credentials{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreaws.Credentials{}, err
	}
	return credential, nil
}

func (s *CoreAWSStore) UpdateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential coreaws.Credentials, expected int64) (coreaws.Credentials, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil ||
		credential.Validate() != nil || credential.Revision != expected+1 {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(credential)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreaws.Credentials{}, err
	}
	defer tx.Rollback(ctx)
	if err = requireGuardedCredentialMutation(ctx, tx, scope); err != nil {
		return coreaws.Credentials{}, err
	}
	configured := credentialSessionConfigured(credential)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credentials SET name=$2,region=$3,secret_key_version=$4,access_key_id_nonce=$5,access_key_id_ciphertext=$6,secret_access_key_nonce=$7,secret_access_key_ciphertext=$8,session_token_nonce=$9,session_token_ciphertext=$10,session_token_configured=$11,account_id=$12,user_arn=$13,verified_revision=$14,revision=$15,tested_at=$16,updated_at=$17 WHERE credential_id=$1 AND revision=$18 AND owner_id=$19 AND account_generation=$20`, credential.ID, credential.Name, credential.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, credential.AccountID, credential.UserARN, credential.VerifiedRevision, credential.Revision, nullableCredentialTime(credential.TestedAt), credential.UpdatedAt, expected, scope.OwnerID, scope.AccountGeneration)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	loaded, err := s.scanCredentialRow(tx.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1`, credential.ID))
	if err != nil {
		return coreaws.Credentials{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreaws.Credentials{}, err
	}
	return loaded, nil
}

func (s *CoreAWSStore) DeleteCredentialGuarded(ctx context.Context, scope coreteam.Scope, id string, expected int64) error {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || expected < 1 {
		return coreaws.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = requireGuardedCredentialMutation(ctx, tx, scope); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM core_aws_credentials WHERE credential_id=$1 AND revision=$2 AND owner_id=$3 AND account_generation=$4`, id, expected, scope.OwnerID, scope.AccountGeneration)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coreaws.ErrRevisionConflict
	}
	return tx.Commit(ctx)
}

func requireGuardedCredentialMutation(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	if err := requireTeamAdmission(ctx, tx, scope); err != nil {
		return err
	}
	if err := lockTeamCredentialMutation(ctx, tx, scope); err != nil {
		return err
	}
	return requireNoActiveTeamExecutionTx(ctx, tx, scope)
}

var _ coreaws.GuardedCredentialRepository = (*CoreAWSStore)(nil)

type credentialReplayRow interface{ Scan(...any) error }

func readCredentialMutationReplay(row credentialReplayRow, digest string) (coreaws.CredentialMutationReplay, bool, error) {
	var storedDigest string
	var response []byte
	var deleted bool
	if err := row.Scan(&storedDigest, &response, &deleted); errors.Is(err, pgx.ErrNoRows) {
		return coreaws.CredentialMutationReplay{}, false, nil
	} else if err != nil {
		return coreaws.CredentialMutationReplay{}, false, err
	}
	if storedDigest != digest {
		return coreaws.CredentialMutationReplay{}, true, coreaws.ErrIdempotencyConflict
	}
	replay := coreaws.CredentialMutationReplay{Deleted: deleted}
	if !deleted && json.Unmarshal(response, &replay.Credential) != nil {
		return coreaws.CredentialMutationReplay{}, true, coreaws.ErrConflict
	}
	return replay, true, nil
}

func (s *CoreAWSStore) ReplayCredentialMutation(ctx context.Context, scope coreteam.Scope, operation, key, digest string) (coreaws.CredentialMutationReplay, bool, error) {
	if s == nil || s.store == nil || scope.Validate() != nil || operation == "" || key == "" || digest == "" {
		return coreaws.CredentialMutationReplay{}, false, coreaws.ErrInvalid
	}
	return readCredentialMutationReplay(s.store.pool.QueryRow(ctx, `SELECT request_hash,response_json,deleted FROM core_aws_credential_replays WHERE owner_id=$1 AND account_generation=$2 AND operation=$3 AND idempotency_key=$4`, scope.OwnerID, scope.AccountGeneration, operation, key), digest)
}

func writeCredentialMutationReplay(ctx context.Context, tx pgx.Tx, scope coreteam.Scope, operation, key, digest string, view coreaws.CredentialView, deleted bool) error {
	response, err := json.Marshal(view)
	if err != nil {
		return coreaws.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_aws_credential_replays(owner_id,account_generation,operation,idempotency_key,request_hash,response_json,deleted) VALUES($1,$2,$3,$4,$5,$6,$7)`, scope.OwnerID, scope.AccountGeneration, operation, key, digest, response, deleted)
	return err
}

func beginCredentialMutation(ctx context.Context, store *Store, scope coreteam.Scope, operation, key, digest string) (pgx.Tx, coreaws.CredentialMutationReplay, bool, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, coreaws.CredentialMutationReplay{}, false, err
	}
	if err = requireTeamAdmission(ctx, tx, scope); err != nil {
		tx.Rollback(ctx)
		return nil, coreaws.CredentialMutationReplay{}, false, err
	}
	if err = lockTeamCredentialMutation(ctx, tx, scope); err != nil {
		tx.Rollback(ctx)
		return nil, coreaws.CredentialMutationReplay{}, false, err
	}
	replay, found, err := readCredentialMutationReplay(tx.QueryRow(ctx, `SELECT request_hash,response_json,deleted FROM core_aws_credential_replays WHERE owner_id=$1 AND account_generation=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, operation, key), digest)
	if err != nil || found {
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
		return nil, replay, found, err
	}
	if err = requireNoActiveTeamExecutionTx(ctx, tx, scope); err != nil {
		tx.Rollback(ctx)
		return nil, coreaws.CredentialMutationReplay{}, false, err
	}
	return tx, coreaws.CredentialMutationReplay{}, false, nil
}

func (s *CoreAWSStore) CreateCredentialGuardedIdempotent(ctx context.Context, scope coreteam.Scope, credential coreaws.Credentials, key, digest string) (coreaws.CredentialView, error) {
	if s == nil || s.store == nil || scope.Validate() != nil || credential.Validate() != nil {
		return coreaws.CredentialView{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(credential)
	if err != nil {
		return coreaws.CredentialView{}, err
	}
	tx, replay, found, err := beginCredentialMutation(ctx, s.store, scope, coreaws.CredentialMutationCreate, key, digest)
	if err != nil || found {
		return replay.Credential, err
	}
	defer tx.Rollback(ctx)
	configured := credentialSessionConfigured(credential)
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,owner_id,account_generation,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, credential.ID, scope.OwnerID, scope.AccountGeneration, credential.Name, credential.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, credential.AccountID, credential.UserARN, credential.VerifiedRevision, credential.Revision, nullableCredentialTime(credential.TestedAt), credential.CreatedAt, credential.UpdatedAt); err != nil {
		return coreaws.CredentialView{}, err
	}
	view := credential.View()
	if err = writeCredentialMutationReplay(ctx, tx, scope, coreaws.CredentialMutationCreate, key, digest, view, false); err != nil {
		return coreaws.CredentialView{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreaws.CredentialView{}, err
	}
	return view, nil
}

func (s *CoreAWSStore) UpdateCredentialGuardedIdempotent(ctx context.Context, scope coreteam.Scope, credential coreaws.Credentials, expected int64, key, digest string) (coreaws.CredentialView, error) {
	if s == nil || s.store == nil || scope.Validate() != nil || credential.Validate() != nil || credential.Revision != expected+1 {
		return coreaws.CredentialView{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(credential)
	if err != nil {
		return coreaws.CredentialView{}, err
	}
	tx, replay, found, err := beginCredentialMutation(ctx, s.store, scope, coreaws.CredentialMutationReplace, key, digest)
	if err != nil || found {
		return replay.Credential, err
	}
	defer tx.Rollback(ctx)
	configured := credentialSessionConfigured(credential)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credentials SET name=$2,region=$3,secret_key_version=$4,access_key_id_nonce=$5,access_key_id_ciphertext=$6,secret_access_key_nonce=$7,secret_access_key_ciphertext=$8,session_token_nonce=$9,session_token_ciphertext=$10,session_token_configured=$11,account_id=$12,user_arn=$13,verified_revision=$14,revision=$15,tested_at=$16,updated_at=$17 WHERE credential_id=$1 AND revision=$18 AND owner_id=$19 AND account_generation=$20`, credential.ID, credential.Name, credential.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, credential.AccountID, credential.UserARN, credential.VerifiedRevision, credential.Revision, nullableCredentialTime(credential.TestedAt), credential.UpdatedAt, expected, scope.OwnerID, scope.AccountGeneration)
	if err != nil {
		return coreaws.CredentialView{}, err
	}
	if tag.RowsAffected() != 1 {
		return coreaws.CredentialView{}, coreaws.ErrRevisionConflict
	}
	view := credential.View()
	if err = writeCredentialMutationReplay(ctx, tx, scope, coreaws.CredentialMutationReplace, key, digest, view, false); err != nil {
		return coreaws.CredentialView{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreaws.CredentialView{}, err
	}
	return view, nil
}

func (s *CoreAWSStore) DeleteCredentialGuardedIdempotent(ctx context.Context, scope coreteam.Scope, id string, expected int64, key, digest string) error {
	if s == nil || s.store == nil || scope.Validate() != nil || expected < 1 {
		return coreaws.ErrInvalid
	}
	tx, _, found, err := beginCredentialMutation(ctx, s.store, scope, coreaws.CredentialMutationDelete, key, digest)
	if err != nil || found {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM core_aws_credentials WHERE credential_id=$1 AND revision=$2 AND owner_id=$3 AND account_generation=$4`, id, expected, scope.OwnerID, scope.AccountGeneration)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return coreaws.ErrRevisionConflict
	}
	if err = writeCredentialMutationReplay(ctx, tx, scope, coreaws.CredentialMutationDelete, key, digest, coreaws.CredentialView{ID: id, Revision: expected}, true); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var _ coreaws.DurableCredentialMutationRepository = (*CoreAWSStore)(nil)
