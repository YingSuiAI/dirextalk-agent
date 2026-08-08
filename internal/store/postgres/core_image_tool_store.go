package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreImageToolStore struct{ store *Store }

func NewCoreImageToolStore(store *Store) *CoreImageToolStore {
	return &CoreImageToolStore{store: store}
}

type imageToolRecord struct {
	UploadID, SourceID, OwnerID, ImageRequestID, BeginKey, BeginDigest, Name, MIMEType, ContentSHA256, Status string
	AccountGeneration                                                                                         int64
	DeclaredSize, ReceivedSize, Revision                                                                      uint64
	NextOrdinal                                                                                               uint32
	ExpiresAt, CreatedAt, UpdatedAt                                                                           time.Time
	Content                                                                                                   []byte
}

func (s *CoreImageToolStore) Begin(ctx context.Context, c coreimagetool.BeginCommand) (coreimagetool.Upload, error) {
	if s == nil || s.store == nil || ctx == nil {
		return coreimagetool.Upload{}, coreimagetool.ErrInvalid
	}
	if err := NewCoreDeprovisionStore(s.store.pool).CheckAdmission(ctx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Upload{}, err
	}
	digest := imageToolDigest(struct {
		OwnerID                        string
		AccountGeneration              int64
		ImageRequestID, Name, MIMEType string
		DeclaredSize                   uint64
		ContentSHA256                  string
	}{strings.TrimSpace(c.OwnerID), c.AccountGeneration, c.ImageRequestID, c.Name, c.MIMEType, c.DeclaredSize, c.ContentSHA256})
	uploadID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("image-tool-upload:"+c.IdempotencyKey)).String()
	sourceID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("image-tool-source:"+c.IdempotencyKey)).String()
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockImageToolAdmission(ctx, tx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Upload{}, err
	}
	if err = cleanupExpiredImages(ctx, tx); err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	var existing imageToolRecord
	if err = scanImageTool(ctx, tx, "begin_idempotency_key=$1", []any{c.IdempotencyKey}, &existing); err == nil {
		defer clear(existing.Content)
		if existing.BeginDigest != digest || existing.OwnerID != strings.TrimSpace(c.OwnerID) || existing.AccountGeneration != c.AccountGeneration || existing.ImageRequestID != c.ImageRequestID {
			return coreimagetool.Upload{}, coreimagetool.ErrConflict
		}
		if tx.Commit(ctx) != nil {
			return coreimagetool.Upload{}, coreimagetool.ErrRepository
		}
		return imageBeginUpload(existing), nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	var conflict bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_image_tool_uploads WHERE owner_id=$1 AND account_generation=$2 AND image_request_id=$3)`, strings.TrimSpace(c.OwnerID), c.AccountGeneration, c.ImageRequestID).Scan(&conflict); err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	if conflict {
		return coreimagetool.Upload{}, coreimagetool.ErrConflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(coreimagetool.UploadTTL)
	_, err = tx.Exec(ctx, `INSERT INTO core_image_tool_uploads(upload_id,source_id,owner_id,account_generation,image_request_id,begin_idempotency_key,begin_request_digest,name,mime_type,declared_size,content_sha256,status,revision,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'receiving',1,$12,$13,$13)`, uploadID, sourceID, strings.TrimSpace(c.OwnerID), c.AccountGeneration, c.ImageRequestID, c.IdempotencyKey, digest, c.Name, c.MIMEType, c.DeclaredSize, c.ContentSHA256, expires, now)
	if err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	if tx.Commit(ctx) != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	return imageUpload(imageToolRecord{UploadID: uploadID, SourceID: sourceID, OwnerID: strings.TrimSpace(c.OwnerID), AccountGeneration: c.AccountGeneration, ImageRequestID: c.ImageRequestID, Status: "receiving", Revision: 1, ExpiresAt: expires}), nil
}

func (s *CoreImageToolStore) Append(ctx context.Context, c coreimagetool.AppendCommand) (coreimagetool.Upload, error) {
	defer c.Destroy()
	if s == nil || s.store == nil {
		return coreimagetool.Upload{}, coreimagetool.ErrInvalid
	}
	if err := NewCoreDeprovisionStore(s.store.pool).CheckAdmission(ctx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Upload{}, err
	}
	d := sha256.Sum256(c.Data)
	if hex.EncodeToString(d[:]) != c.ChunkSHA256 {
		return coreimagetool.Upload{}, coreimagetool.ErrConflict
	}
	digest := imageToolDigest(struct {
		OwnerID           string
		AccountGeneration int64
		UploadID          string
		ExpectedRevision  uint64
		Ordinal           uint32
		OffsetBytes       uint64
		ChunkSHA256       string
		ChunkSize         int
	}{strings.TrimSpace(c.OwnerID), c.AccountGeneration, c.UploadID, c.ExpectedRevision, c.Ordinal, c.OffsetBytes, c.ChunkSHA256, len(c.Data)})
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockImageToolAdmission(ctx, tx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Upload{}, err
	}
	if value, found, e := loadImageReplay[coreimagetool.Upload](ctx, tx, "append", c.IdempotencyKey, digest, strings.TrimSpace(c.OwnerID), c.AccountGeneration); e != nil || found {
		return value, e
	}
	var r imageToolRecord
	if err = scanImageTool(ctx, tx, "upload_id=$1 FOR UPDATE", []any{c.UploadID}, &r); err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrConflict
	}
	defer clear(r.Content)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if r.OwnerID != strings.TrimSpace(c.OwnerID) || r.AccountGeneration != c.AccountGeneration || r.Status != "receiving" || !now.Before(r.ExpiresAt) || r.Revision != c.ExpectedRevision || r.NextOrdinal != c.Ordinal || r.ReceivedSize != c.OffsetBytes || r.ReceivedSize+uint64(len(c.Data)) > r.DeclaredSize {
		return coreimagetool.Upload{}, coreimagetool.ErrConflict
	}
	next := append(append([]byte(nil), r.Content...), c.Data...)
	defer clear(next)
	r.Content = next
	r.ReceivedSize += uint64(len(c.Data))
	r.NextOrdinal++
	r.Revision++
	r.UpdatedAt = now
	tag, err := tx.Exec(ctx, `UPDATE core_image_tool_uploads SET content_bytes=$2,received_size=$3,next_ordinal=$4,revision=$5,updated_at=$6 WHERE upload_id=$1 AND revision=$7 AND status='receiving'`, r.UploadID, r.Content, r.ReceivedSize, r.NextOrdinal, r.Revision, now, c.ExpectedRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return coreimagetool.Upload{}, coreimagetool.ErrConflict
	}
	value := imageUpload(r)
	if err = storeImageReplay(ctx, tx, "append", c.IdempotencyKey, digest, r.UploadID, value); err != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	if tx.Commit(ctx) != nil {
		return coreimagetool.Upload{}, coreimagetool.ErrRepository
	}
	return value, nil
}

func (s *CoreImageToolStore) Commit(ctx context.Context, c coreimagetool.CommitCommand) (coreimagetool.Source, error) {
	if s == nil || s.store == nil {
		return coreimagetool.Source{}, coreimagetool.ErrInvalid
	}
	if err := NewCoreDeprovisionStore(s.store.pool).CheckAdmission(ctx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Source{}, err
	}
	digest := imageToolDigest(c)
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreimagetool.Source{}, coreimagetool.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockImageToolAdmission(ctx, tx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.Source{}, err
	}
	if value, found, e := loadImageReplay[coreimagetool.Source](ctx, tx, "commit", c.IdempotencyKey, digest, strings.TrimSpace(c.OwnerID), c.AccountGeneration); e != nil || found {
		return value, e
	}
	var r imageToolRecord
	if err = scanImageTool(ctx, tx, "upload_id=$1 FOR UPDATE", []any{c.UploadID}, &r); err != nil {
		return coreimagetool.Source{}, coreimagetool.ErrConflict
	}
	defer clear(r.Content)
	now := time.Now().UTC().Truncate(time.Microsecond)
	actual := sha256.Sum256(r.Content)
	if r.OwnerID != strings.TrimSpace(c.OwnerID) || r.AccountGeneration != c.AccountGeneration || r.Status != "receiving" || !now.Before(r.ExpiresAt) || r.Revision != c.ExpectedRevision || r.ReceivedSize != r.DeclaredSize || c.ContentSHA256 != r.ContentSHA256 || hex.EncodeToString(actual[:]) != r.ContentSHA256 {
		return coreimagetool.Source{}, coreimagetool.ErrConflict
	}
	r.Status = "committed"
	r.Revision++
	r.UpdatedAt = now
	tag, err := tx.Exec(ctx, `UPDATE core_image_tool_uploads SET status='committed',revision=$2,updated_at=$3 WHERE upload_id=$1 AND revision=$4 AND status='receiving'`, r.UploadID, r.Revision, now, c.ExpectedRevision)
	if err != nil || tag.RowsAffected() != 1 {
		return coreimagetool.Source{}, coreimagetool.ErrConflict
	}
	value := imageSource(r)
	if err = storeImageReplay(ctx, tx, "commit", c.IdempotencyKey, digest, r.UploadID, value); err != nil {
		return coreimagetool.Source{}, coreimagetool.ErrRepository
	}
	if tx.Commit(ctx) != nil {
		return coreimagetool.Source{}, coreimagetool.ErrRepository
	}
	return value, nil
}

func (s *CoreImageToolStore) Consume(ctx context.Context, c coreimagetool.ConsumeCommand) (coreimagetool.ConsumedSource, error) {
	if s == nil || s.store == nil {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrInvalid
	}
	if err := NewCoreDeprovisionStore(s.store.pool).CheckAdmission(ctx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.ConsumedSource{}, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrRepository
	}
	defer tx.Rollback(ctx)
	if err = lockImageToolAdmission(ctx, tx, strings.TrimSpace(c.OwnerID), c.AccountGeneration); err != nil {
		return coreimagetool.ConsumedSource{}, err
	}
	var r imageToolRecord
	if err = scanImageTool(ctx, tx, "source_id=$1 FOR UPDATE", []any{c.SourceID}, &r); errors.Is(err, pgx.ErrNoRows) {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrNotFound
	} else if err != nil {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrRepository
	}
	defer clear(r.Content)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if r.OwnerID != strings.TrimSpace(c.OwnerID) || r.AccountGeneration != c.AccountGeneration || r.ImageRequestID != c.ImageRequestID || c.SourceRevision != 1 {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrConflict
	}
	if !now.Before(r.ExpiresAt) {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrExpired
	}
	if r.Status == "consumed" {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrConsumed
	}
	if r.Status != "committed" || r.ReceivedSize != r.DeclaredSize {
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrConflict
	}
	content := append([]byte(nil), r.Content...)
	tag, err := tx.Exec(ctx, `UPDATE core_image_tool_uploads SET status='consumed',content_bytes=''::bytea,received_size=0,revision=revision+1,consumed_at=$2,updated_at=$2 WHERE upload_id=$1 AND status='committed'`, r.UploadID, now)
	if err != nil || tag.RowsAffected() != 1 {
		clear(content)
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrConflict
	}
	if tx.Commit(ctx) != nil {
		clear(content)
		return coreimagetool.ConsumedSource{}, coreimagetool.ErrRepository
	}
	return coreimagetool.ConsumedSource{Source: imageSource(r), Content: content}, nil
}

func scanImageTool(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, where string, args []any, out *imageToolRecord) error {
	return q.QueryRow(ctx, `SELECT upload_id::text,source_id::text,owner_id,account_generation,image_request_id::text,begin_idempotency_key::text,begin_request_digest,name,mime_type,declared_size,content_sha256,content_bytes,received_size,next_ordinal,status,revision,expires_at,created_at,updated_at FROM core_image_tool_uploads WHERE `+where, args...).Scan(&out.UploadID, &out.SourceID, &out.OwnerID, &out.AccountGeneration, &out.ImageRequestID, &out.BeginKey, &out.BeginDigest, &out.Name, &out.MIMEType, &out.DeclaredSize, &out.ContentSHA256, &out.Content, &out.ReceivedSize, &out.NextOrdinal, &out.Status, &out.Revision, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt)
}
func imageUpload(r imageToolRecord) coreimagetool.Upload {
	return coreimagetool.Upload{UploadID: r.UploadID, SourceID: r.SourceID, ImageRequestID: r.ImageRequestID, Status: r.Status, ReceivedSize: r.ReceivedSize, MaxChunkBytes: coreimagetool.MaxChunkBytes, Revision: r.Revision, ExpiresAt: r.ExpiresAt.UTC()}
}
func imageBeginUpload(r imageToolRecord) coreimagetool.Upload {
	return coreimagetool.Upload{UploadID: r.UploadID, SourceID: r.SourceID, ImageRequestID: r.ImageRequestID, Status: "receiving", ReceivedSize: 0, MaxChunkBytes: coreimagetool.MaxChunkBytes, Revision: 1, ExpiresAt: r.ExpiresAt.UTC()}
}
func imageSource(r imageToolRecord) coreimagetool.Source {
	return coreimagetool.Source{SourceID: r.SourceID, Revision: 1, ImageRequestID: r.ImageRequestID, Name: r.Name, MIMEType: r.MIMEType, SizeBytes: r.DeclaredSize, SHA256: r.ContentSHA256, Status: "committed", ExpiresAt: r.ExpiresAt.UTC()}
}
func imageToolDigest(v any) string {
	raw, _ := json.Marshal(v)
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}
func loadImageReplay[T any](ctx context.Context, tx pgx.Tx, op, key, digest, owner string, generation int64) (T, bool, error) {
	var zero T
	var stored string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT r.request_digest,r.response_json FROM core_image_tool_replays r JOIN core_image_tool_uploads u ON u.upload_id=r.upload_id WHERE r.operation=$1 AND r.idempotency_key=$2 AND u.owner_id=$3 AND u.account_generation=$4`, op, key, owner, generation).Scan(&stored, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil || stored != digest || json.Unmarshal(raw, &zero) != nil {
		return zero, false, coreimagetool.ErrConflict
	}
	return zero, true, nil
}
func storeImageReplay(ctx context.Context, tx pgx.Tx, op, key, digest, uploadID string, v any) error {
	raw, _ := json.Marshal(v)
	_, err := tx.Exec(ctx, `INSERT INTO core_image_tool_replays(operation,idempotency_key,request_digest,upload_id,response_json) VALUES($1,$2,$3,$4,$5)`, op, key, digest, uploadID, raw)
	return err
}
func cleanupExpiredImages(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `DELETE FROM core_image_tool_uploads WHERE expires_at<=clock_timestamp()`)
	return err
}

func lockImageToolAdmission(ctx context.Context, tx pgx.Tx, owner string, generation int64) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return coreimagetool.ErrRepository
	}
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, owner, generation).Scan(&fenced); err != nil {
		return coreimagetool.ErrRepository
	}
	if fenced {
		return coreimagetool.ErrRepository
	}
	return nil
}

var _ coreimagetool.Repository = (*CoreImageToolStore)(nil)
