package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreAWSStore struct{ store *Store }

func NewCoreAWSStore(s *Store) *CoreAWSStore { return &CoreAWSStore{store: s} }
func secretCredential(c coreaws.Credentials, a, s, t []byte) coreaws.Credentials { // restore private bytes for provider use; never serialized/logged
	return coreaws.RehydrateCredentials(c.ID, c.Name, c.Region, c.AccountID, c.UserARN, a, s, t, c.VerifiedRevision, c.Revision, c.CreatedAt, c.UpdatedAt)
}
func credArgs(c coreaws.Credentials) ([]byte, []byte, []byte) {
	return c.StoredSecretBytes()
}
func (s *CoreAWSStore) CreateCredential(ctx context.Context, c coreaws.Credentials) (coreaws.Credentials, error) {
	if c.Validate() != nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	a, se, t := credArgs(c)
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,name,region,access_key_id,secret_access_key,session_token,account_id,user_arn,verified_revision,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.ID, c.Name, c.Region, a, se, t, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, c.CreatedAt, c.UpdatedAt)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	return c, nil
}
func (s *CoreAWSStore) GetCredential(ctx context.Context, id string) (coreaws.Credentials, error) {
	var c coreaws.Credentials
	var a, se, t []byte
	e := s.store.pool.QueryRow(ctx, `SELECT credential_id::text,name,region,access_key_id,secret_access_key,session_token,account_id,user_arn,verified_revision,revision,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1`, id).Scan(&c.ID, &c.Name, &c.Region, &a, &se, &t, &c.AccountID, &c.UserARN, &c.VerifiedRevision, &c.Revision, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, coreaws.ErrNotFound
	}
	if e != nil {
		return c, e
	}
	return secretCredential(c, a, se, t), nil
}
func (s *CoreAWSStore) ListCredentials(ctx context.Context, size int, token string) (coreaws.CredentialPage, error) {
	if size < 0 || size > 100 {
		return coreaws.CredentialPage{}, coreaws.ErrInvalid
	}
	rows, e := s.store.pool.Query(ctx, `SELECT credential_id::text,name,region,account_id,user_arn,revision,created_at,updated_at,(length(access_key_id)>0),(length(secret_access_key)>0),(length(session_token)>0) FROM core_aws_credentials WHERE credential_id::text>$1 ORDER BY credential_id LIMIT $2`, token, size+1)
	if e != nil {
		return coreaws.CredentialPage{}, e
	}
	defer rows.Close()
	var out []coreaws.CredentialView
	for rows.Next() {
		var v coreaws.CredentialView
		if e = rows.Scan(&v.ID, &v.Name, &v.Region, &v.AccountID, &v.UserARN, &v.Revision, &v.CreatedAt, &v.UpdatedAt, &v.HasAccessKey, &v.HasSecretKey, &v.HasSessionToken); e != nil {
			return coreaws.CredentialPage{}, e
		}
		out = append(out, v)
	}
	page := coreaws.CredentialPage{Items: out}
	if len(out) > size {
		page.Items = out[:size]
		if size > 0 {
			page.NextPageToken = page.Items[len(page.Items)-1].ID
		}
	}
	return page, rows.Err()
}
func (s *CoreAWSStore) UpdateCredential(ctx context.Context, c coreaws.Credentials, expected int64) (coreaws.Credentials, error) {
	if c.Validate() != nil || c.Revision != expected+1 {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	a, se, t := credArgs(c)
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET name=$2,region=$3,access_key_id=$4,secret_access_key=$5,session_token=$6,account_id=$7,user_arn=$8,verified_revision=$9,revision=$10,updated_at=$11 WHERE credential_id=$1 AND revision=$12`, c.ID, c.Name, c.Region, a, se, t, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, c.UpdatedAt, expected)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	return s.GetCredential(ctx, c.ID)
}
func (s *CoreAWSStore) DeleteCredential(ctx context.Context, id string, expected int64) error {
	tag, e := s.store.pool.Exec(ctx, `DELETE FROM core_aws_credentials WHERE credential_id=$1 AND revision=$2`, id, expected)
	if e == nil && tag.RowsAffected() == 0 {
		return coreaws.ErrRevisionConflict
	}
	return e
}
func (s *CoreAWSStore) RecordCredentialIdentity(ctx context.Context, id string, rev int64, i coreaws.Identity) (coreaws.Credentials, error) {
	_, e := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET account_id=$2,user_arn=$3,verified_revision=$4,updated_at=clock_timestamp() WHERE credential_id=$1 AND revision=$4`, id, i.AccountID, i.UserARN, rev)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	return s.GetCredential(ctx, id)
}
func (s *CoreAWSStore) CreatePlan(ctx context.Context, p coreaws.Plan) (coreaws.Plan, error) {
	if p.Validate() != nil {
		return p, coreaws.ErrInvalid
	}
	pj, _ := json.Marshal(p.Parameters)
	tj, _ := json.Marshal(p.Tags)
	cj, _ := json.Marshal(p.Capabilities)
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, p.ID, p.CredentialID, p.Region, p.StackName, p.Operation, p.Template, p.TemplateSHA256, pj, tj, cj, p.Revision, p.CreatedAt)
	return p, e
}
func (s *CoreAWSStore) GetPlan(ctx context.Context, id string) (coreaws.Plan, error) {
	var p coreaws.Plan
	var op string
	var pj, tj, cj []byte
	e := s.store.pool.QueryRow(ctx, `SELECT plan_id::text,credential_id::text,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at FROM core_aws_plans WHERE plan_id=$1`, id).Scan(&p.ID, &p.CredentialID, &p.Region, &p.StackName, &op, &p.Template, &p.TemplateSHA256, &pj, &tj, &cj, &p.Revision, &p.CreatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, coreaws.ErrNotFound
	}
	if e != nil {
		return p, e
	}
	p.Operation = coreaws.Operation(op)
	_ = json.Unmarshal(pj, &p.Parameters)
	_ = json.Unmarshal(tj, &p.Tags)
	_ = json.Unmarshal(cj, &p.Capabilities)
	return p, nil
}
func (s *CoreAWSStore) ListPlans(ctx context.Context, size int, token string) (coreaws.PlanPage, error) {
	rows, e := s.store.pool.Query(ctx, `SELECT plan_id::text FROM core_aws_plans WHERE plan_id::text>$1 ORDER BY plan_id LIMIT $2`, token, size+1)
	if e != nil {
		return coreaws.PlanPage{}, e
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	page := coreaws.PlanPage{}
	for i, id := range ids {
		if i >= size {
			if len(page.Items) > 0 {
				page.NextPageToken = page.Items[len(page.Items)-1].ID
			}
			break
		}
		p, e := s.GetPlan(ctx, id)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, p.View())
	}
	return page, rows.Err()
}
func (s *CoreAWSStore) CreateChange(ctx context.Context, c coreaws.Change) (coreaws.Change, error) {
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, c.ID, c.PlanID, c.CredentialID, c.TaskID, c.ConfirmationID, c.Operation, c.Status, c.Stage, c.ChangeSetID, c.ProviderRequestDigest, c.ProviderToken, c.Revision, c.ErrorCode, c.ErrorSummary, c.CreatedAt, c.UpdatedAt)
	return c, e
}
func (s *CoreAWSStore) GetChange(ctx context.Context, id string) (coreaws.Change, error) {
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, id))
}
func (s *CoreAWSStore) GetChangeByConfirmation(ctx context.Context, id string) (coreaws.Change, error) {
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE confirmation_id=$1`, id))
}

// ListChanges returns a stable lexicographic cursor over change IDs.
func (s *CoreAWSStore) ListChanges(ctx context.Context, size int, planID, token string) (coreaws.Page[coreaws.Change], error) {
	if size < 0 || size > 100 {
		return coreaws.Page[coreaws.Change]{}, coreaws.ErrInvalid
	}
	lastID, err := changeCursor(planID, token)
	if err != nil {
		return coreaws.Page[coreaws.Change]{}, coreaws.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT change_id::text FROM core_aws_changes WHERE ($1='' OR plan_id::text=$1) AND change_id::text>$2 ORDER BY change_id LIMIT $3`, planID, lastID, size+1)
	if err != nil {
		return coreaws.Page[coreaws.Change]{}, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return coreaws.Page[coreaws.Change]{}, err
		}
		ids = append(ids, id)
	}
	page := coreaws.Page[coreaws.Change]{}
	for i, id := range ids {
		if i >= size {
			page.NextPageToken = makeChangeCursor(planID, page.Items[len(page.Items)-1].ID)
			break
		}
		v, e := s.GetChange(ctx, id)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

// A change cursor is bound to its filter.  Its key is the last emitted row,
// never the look-ahead row, so the next query cannot skip an item.
func makeChangeCursor(planID, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(planID + "\x00" + id))
}
func changeCursor(planID, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 2 || parts[0] != planID || uuid.Validate(parts[1]) != nil {
		return "", errors.New("invalid cursor")
	}
	return parts[1], nil
}
func (s *CoreAWSStore) scanChange(row interface{ Scan(...any) error }) (coreaws.Change, error) {
	var c coreaws.Change
	var op, st, stage string
	e := row.Scan(&c.ID, &c.PlanID, &c.CredentialID, &c.TaskID, &c.ConfirmationID, &op, &st, &stage, &c.ChangeSetID, &c.ProviderRequestDigest, &c.ProviderToken, &c.Revision, &c.ErrorCode, &c.ErrorSummary, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, coreaws.ErrNotFound
	}
	c.Operation = coreaws.Operation(op)
	c.Status = coreaws.ChangeStatus(st)
	c.Stage = coreaws.ChangeStage(stage)
	return c, e
}
func (s *CoreAWSStore) UpdateChange(ctx context.Context, c coreaws.Change, expected int64) (coreaws.Change, error) {
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_changes SET status=$2,stage=$3,change_set_id=$4,provider_request_digest=$5,provider_token=$6,revision=$7,error_code=$8,error_summary=$9,updated_at=$10 WHERE change_id=$1 AND revision=$11`, c.ID, c.Status, c.Stage, c.ChangeSetID, c.ProviderRequestDigest, c.ProviderToken, c.Revision, c.ErrorCode, c.ErrorSummary, c.UpdatedAt, expected)
	if e == nil && tag.RowsAffected() == 0 {
		return c, coreaws.ErrRevisionConflict
	}
	return c, e
}
