package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreExtensionStore) BuiltinSkillSeeded(ctx context.Context, candidateID string) (bool, error) {
	if s == nil || s.store == nil || candidateID == "" {
		return false, coreextension.ErrInvalid
	}
	var installationID string
	err := s.store.pool.QueryRow(ctx, `SELECT installation_id::text FROM core_builtin_skill_seeds WHERE candidate_id=$1`, candidateID).Scan(&installationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if uuid.Validate(installationID) != nil {
		return false, coreextension.ErrConflict
	}
	return true, nil
}

// EnsureBuiltinSkill records one already-published immutable Skill as an
// ordinary installed extension. The seed row is never removed by uninstall,
// which makes an owner's removal durable across process restarts.
func (s *CoreExtensionStore) EnsureBuiltinSkill(ctx context.Context, artifact coreextension.FetchArtifact, artifactDigest string) (coreextension.Installation, error) {
	if s == nil || s.store == nil || artifact.Validate() != nil || artifact.Candidate.Kind != coreextension.KindSkill || artifact.Candidate.Source != coreextension.SourceBuiltin || !coretask.ValidDigest(artifactDigest) {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	installationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:builtin-skill:installation:"+artifact.Candidate.ID))
	versionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:builtin-skill:version:"+artifact.Candidate.ID+":"+artifact.Candidate.Pin.RegistryVersion+":"+artifact.ContentDigest))
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return coreextension.Installation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('core_builtin_skill_seeds',0))`); err != nil {
		return coreextension.Installation{}, err
	}
	var existingID string
	err = tx.QueryRow(ctx, `SELECT installation_id::text FROM core_builtin_skill_seeds WHERE candidate_id=$1 FOR UPDATE`, artifact.Candidate.ID).Scan(&existingID)
	if err == nil {
		if err = tx.Commit(ctx); err != nil {
			return coreextension.Installation{}, err
		}
		return s.Get(ctx, existingID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreextension.Installation{}, err
	}
	now := time.Now().UTC()
	mutation := coreextension.Mutation{Candidate: artifact.Candidate, Inspection: artifact.Inspection, ArtifactPath: artifactDigest, ArtifactDigest: artifactDigest}
	version := versionFromInspectionPG(artifact.Inspection, versionID, now, mutation)
	installation := coreextension.Installation{
		ID: installationID.String(), Candidate: artifact.Candidate, Kind: coreextension.KindSkill,
		Source: coreextension.SourceBuiltin, CandidateID: artifact.Candidate.ID, Name: artifact.Candidate.Name,
		Description: artifact.Candidate.Description, Transport: coreextension.TransportSkillStatic,
		Revision: 1, State: coreextension.StateInstalled, Enabled: true,
		ActiveVersionID: versionID.String(), Versions: []coreextension.VersionRecord{version},
		CreatedAt: now, UpdatedAt: now,
	}
	candidateJSON, _ := json.Marshal(installation.Candidate)
	versionJSON, _ := json.Marshal(version)
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,proposed_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,$2,'skill','builtin',$3,$4,$5,'skill_static',1,'installed',true,$6,NULL,'[]'::jsonb,'[]'::jsonb,$7,$7)`, installationID, candidateJSON, installation.CandidateID, installation.Name, installation.Description, versionID, now); err != nil {
		return coreextension.Installation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, installationID, versionJSON, now); err != nil {
		return coreextension.Installation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_builtin_skill_seeds(candidate_id,registry_version,content_digest,artifact_digest,installation_id,seeded_at) VALUES($1,$2,$3,$4,$5,$6)`, artifact.Candidate.ID, artifact.Candidate.Pin.RegistryVersion, artifact.ContentDigest, artifactDigest, installationID, now); err != nil {
		return coreextension.Installation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreextension.Installation{}, err
	}
	return s.Get(ctx, installationID.String())
}
