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

func (s *CoreExtensionStore) BuiltinMCPSeeded(ctx context.Context, candidateID string) (bool, error) {
	if s == nil || s.store == nil || candidateID == "" {
		return false, coreextension.ErrInvalid
	}
	var installationID string
	err := s.store.pool.QueryRow(ctx, `SELECT installation_id::text FROM core_builtin_mcp_seeds WHERE candidate_id=$1`, candidateID).Scan(&installationID)
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

// EnsureBuiltinMCP records one already-published immutable MCP server as an
// ordinary installed extension. The retained seed makes an owner's removal
// durable across process restarts.
func (s *CoreExtensionStore) EnsureBuiltinMCP(ctx context.Context, artifact coreextension.FetchArtifact, artifactDigest string) (coreextension.Installation, error) {
	if s == nil || s.store == nil || artifact.Validate() != nil || artifact.Candidate.Kind != coreextension.KindMCP || artifact.Candidate.Source != coreextension.SourceBuiltin || !coretask.ValidDigest(artifactDigest) {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	installationID := uuid.MustParse(coreextension.BuiltinMCPInstallationID(artifact.Candidate.ID))
	versionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:builtin-mcp:version:"+artifact.Candidate.ID+":"+artifact.Candidate.Pin.RegistryVersion+":"+artifact.ContentDigest))
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return coreextension.Installation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('core_builtin_mcp_seeds',0))`); err != nil {
		return coreextension.Installation{}, err
	}
	now := time.Now().UTC()
	mutation := coreextension.Mutation{Candidate: artifact.Candidate, Inspection: artifact.Inspection, ArtifactPath: artifactDigest, ArtifactDigest: artifactDigest}
	version := versionFromInspectionPG(artifact.Inspection, versionID, now, mutation)
	var existingID, registryVersion, contentDigest, existingArtifactDigest string
	err = tx.QueryRow(ctx, `SELECT installation_id::text,registry_version,content_digest,artifact_digest FROM core_builtin_mcp_seeds WHERE candidate_id=$1 FOR UPDATE`, artifact.Candidate.ID).Scan(&existingID, &registryVersion, &contentDigest, &existingArtifactDigest)
	if err == nil {
		if registryVersion == artifact.Candidate.Pin.RegistryVersion && contentDigest == artifact.ContentDigest && existingArtifactDigest == artifactDigest {
			if err = tx.Commit(ctx); err != nil {
				return coreextension.Installation{}, err
			}
			return s.Get(ctx, existingID)
		}
		var state string
		var enabled bool
		if err = tx.QueryRow(ctx, `SELECT state,enabled FROM core_extension_installations WHERE installation_id=$1 FOR UPDATE`, existingID).Scan(&state, &enabled); err != nil {
			return coreextension.Installation{}, err
		}
		if state != string(coreextension.StateInstalled) || !enabled {
			if err = tx.Commit(ctx); err != nil {
				return coreextension.Installation{}, err
			}
			return s.Get(ctx, existingID)
		}
		candidateJSON, _ := json.Marshal(artifact.Candidate)
		versionJSON, _ := json.Marshal(version)
		if _, err = tx.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, existingID, versionJSON, now); err != nil {
			return coreextension.Installation{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_extension_installations SET candidate_json=$2,name=$3,description=$4,revision=revision+1,active_version_id=$5,proposed_version_id=NULL,updated_at=$6 WHERE installation_id=$1`, existingID, candidateJSON, artifact.Candidate.Name, artifact.Candidate.Description, versionID, now); err != nil {
			return coreextension.Installation{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_builtin_mcp_seeds SET registry_version=$2,content_digest=$3,artifact_digest=$4,seeded_at=$5 WHERE candidate_id=$1`, artifact.Candidate.ID, artifact.Candidate.Pin.RegistryVersion, artifact.ContentDigest, artifactDigest, now); err != nil {
			return coreextension.Installation{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return coreextension.Installation{}, err
		}
		return s.Get(ctx, existingID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreextension.Installation{}, err
	}
	installation := coreextension.Installation{
		ID: installationID.String(), Candidate: artifact.Candidate, Kind: coreextension.KindMCP,
		Source: coreextension.SourceBuiltin, CandidateID: artifact.Candidate.ID, Name: artifact.Candidate.Name,
		Description: artifact.Candidate.Description, Transport: coreextension.TransportStdioStatic,
		Revision: 1, State: coreextension.StateInstalled, Enabled: true,
		ActiveVersionID: versionID.String(), Versions: []coreextension.VersionRecord{version},
		CreatedAt: now, UpdatedAt: now,
	}
	candidateJSON, _ := json.Marshal(installation.Candidate)
	versionJSON, _ := json.Marshal(version)
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,proposed_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,$2,'mcp','builtin',$3,$4,$5,'stdio_static',1,'installed',true,$6,NULL,'[]'::jsonb,'[]'::jsonb,$7,$7)`, installationID, candidateJSON, installation.CandidateID, installation.Name, installation.Description, versionID, now); err != nil {
		return coreextension.Installation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, installationID, versionJSON, now); err != nil {
		return coreextension.Installation{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_builtin_mcp_seeds(candidate_id,registry_version,content_digest,artifact_digest,installation_id,seeded_at) VALUES($1,$2,$3,$4,$5,$6)`, artifact.Candidate.ID, artifact.Candidate.Pin.RegistryVersion, artifact.ContentDigest, artifactDigest, installationID, now); err != nil {
		return coreextension.Installation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreextension.Installation{}, err
	}
	return s.Get(ctx, installationID.String())
}
