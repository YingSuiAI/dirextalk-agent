package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *CoreExtensionStore) Get(ctx context.Context, id string) (coreextension.Installation, error) {
	if uuid.Validate(id) != nil {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	query := `SELECT installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,COALESCE(active_version_id::text,''),COALESCE(proposed_version_id::text,''),network_grants_json,secret_grants_json,created_at,updated_at FROM core_extension_installations WHERE installation_id=$1`
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		return s.getTx(ctx, s.store.pool.QueryRow(ctx, query+` AND owner_id=$2 AND account_generation=$3`, id, scope.OwnerID, scope.AccountGeneration))
	}
	return s.getTx(ctx, s.store.pool.QueryRow(ctx, query, id))
}

type extScanner interface{ Scan(...any) error }

func (s *CoreExtensionStore) getTx(ctx context.Context, row extScanner) (coreextension.Installation, error) {
	var i coreextension.Installation
	var cand, ng, sg []byte
	var id, kind, source, transport, state, active, proposed string
	if err := row.Scan(&id, &cand, &kind, &source, &i.CandidateID, &i.Name, &i.Description, &transport, &i.Revision, &state, &i.Enabled, &active, &proposed, &ng, &sg, &i.CreatedAt, &i.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return i, coreextension.ErrNotFound
		}
		return i, err
	}
	i.ID = id
	i.Kind = coreextension.Kind(kind)
	i.Source = coreextension.Source(source)
	i.Transport = coreextension.Transport(transport)
	i.State = coreextension.State(state)
	i.ActiveVersionID = active
	i.ProposedVersionID = proposed
	i.Candidate = coreextension.Candidate{}
	if json.Unmarshal(cand, &i.Candidate) != nil {
		return i, coreextension.ErrInvalid
	}
	_ = json.Unmarshal(ng, &i.NetworkGrants)
	_ = json.Unmarshal(sg, &i.SecretGrants)
	rows, err := s.store.pool.Query(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 ORDER BY created_at,version_id`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) == nil {
				var v coreextension.VersionRecord
				if json.Unmarshal(raw, &v) == nil {
					i.Versions = append(i.Versions, v)
				}
			}
		}
	}
	return i, nil
}

func (s *CoreExtensionStore) List(ctx context.Context, q coreextension.ListQuery) (coreextension.InstallationPage, error) {
	lim := q.PageSize
	if lim == 0 {
		lim = 50
	}
	if lim < 0 || lim > 100 {
		return coreextension.InstallationPage{}, coreextension.ErrInvalid
	}
	after := ""
	if q.PageToken != "" {
		b, e := base64.RawURLEncoding.DecodeString(q.PageToken)
		if e != nil || uuid.Validate(string(b)) != nil {
			return coreextension.InstallationPage{}, coreextension.ErrInvalid
		}
		after = string(b)
	}
	ownerID, generation := "", int64(0)
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		ownerID, generation = scope.OwnerID, scope.AccountGeneration
	}
	rows, e := s.store.pool.Query(ctx, `SELECT installation_id FROM core_extension_installations WHERE ($1='' OR installation_id>$1::uuid) AND ($2='' OR kind=$2) AND ($3='' OR source=$3) AND ($4='' OR state=$4) AND ($6='' OR (owner_id=$6 AND account_generation=$7)) ORDER BY installation_id LIMIT $5`, after, string(q.Kind), string(q.Source), string(q.State), lim+1, ownerID, generation)
	if e != nil {
		return coreextension.InstallationPage{}, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	if len(ids) > lim {
		ids = ids[:lim]
	}
	out := coreextension.InstallationPage{Installations: make([]coreextension.Installation, 0, len(ids))}
	for _, id := range ids {
		i, e := s.Get(ctx, id)
		if e != nil {
			return out, e
		}
		out.Installations = append(out.Installations, i)
	}
	if len(ids) == lim {
		var more bool
		_ = s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_extension_installations WHERE installation_id>$1::uuid AND ($2='' OR kind=$2) AND ($3='' OR source=$3) AND ($4='' OR state=$4) AND ($5='' OR (owner_id=$5 AND account_generation=$6)))`, ids[len(ids)-1], string(q.Kind), string(q.Source), string(q.State), ownerID, generation).Scan(&more)
		if more {
			out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(ids[len(ids)-1]))
		}
	}
	return out, nil
}

func (s *CoreExtensionStore) Search(context.Context, coreextension.SearchQuery) (coreextension.Page, error) {
	return coreextension.Page{}, coreextension.ErrNotFound
}
