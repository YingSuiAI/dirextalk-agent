package postgres

import (
	"context"
	"errors"
	"reflect"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CommitConversationStaticSite binds an already verified immutable release to
// the durable turn. No filesystem path is accepted here; the response and
// receipt are derived from the recorded model call by the intrinsic.
func (s *CoreConversationStore) CommitConversationStaticSite(ctx context.Context, command core.ConversationStaticSiteCommand) (core.StaticSiteReceipt, error) {
	command.Response.Message.CreatedAt = command.Response.Message.CreatedAt.UTC().Truncate(time.Microsecond)
	if bindTurnResponseIdentity(&command.Response, command.Lease.Turn.ID) != nil || command.Validate() != nil {
		return core.StaticSiteReceipt{}, core.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return core.StaticSiteReceipt{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_conversation_static_site:"+command.Lease.Turn.ID); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	var stored core.StaticSiteReceipt
	err = tx.QueryRow(ctx, `SELECT site_id::text,release_id::text,public_path,content_sha256,size_bytes FROM core_static_site_releases WHERE turn_id=$1 FOR UPDATE`, command.Lease.Turn.ID).
		Scan(&stored.SiteID, &stored.ReleaseID, &stored.PublicPath, &stored.SHA256, &stored.SizeBytes)
	if err == nil {
		if stored.Validate() != nil || stored.SiteID != command.Receipt.SiteID || stored.ReleaseID != command.Receipt.ReleaseID ||
			stored.PublicPath != command.Receipt.PublicPath || stored.SHA256 != command.Receipt.SHA256 || stored.SizeBytes != command.Receipt.SizeBytes {
			return core.StaticSiteReceipt{}, core.ErrConflict
		}
		var turn core.Turn
		if err = s.scanTurn(ctx, tx, command.Lease.Turn.ID, &turn); err != nil || turn.State != core.TurnCompleted ||
			turn.RequestID != command.Lease.Turn.RequestID || turn.OwnerID != command.Lease.Turn.OwnerID ||
			turn.AccountGeneration != command.Lease.Turn.AccountGeneration || turn.Response == nil ||
			!reflect.DeepEqual(*turn.Response, command.Response) {
			return core.StaticSiteReceipt{}, core.ErrConflict
		}
		stored.AlreadyExists = true
		if err = tx.Commit(ctx); err != nil {
			return core.StaticSiteReceipt{}, err
		}
		return stored, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.StaticSiteReceipt{}, err
	}
	var turn core.Turn
	if err = s.scanTurn(ctx, tx, command.Lease.Turn.ID, &turn); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if turn.State != core.TurnRunning {
		return core.StaticSiteReceipt{}, core.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_static_site_releases(release_id,site_id,owner_id,account_generation,conversation_id,turn_id,request_id,public_path,content_sha256,size_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		command.Receipt.ReleaseID, command.Receipt.SiteID, command.Lease.Turn.OwnerID, command.Lease.Turn.AccountGeneration,
		command.Lease.Turn.ConversationID, command.Lease.Turn.ID, command.Lease.Turn.RequestID, command.Receipt.PublicPath,
		command.Receipt.SHA256, command.Receipt.SizeBytes, command.Response.Message.CreatedAt); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	artifactID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:static-site:"+command.Receipt.ReleaseID)).String()
	if _, err = tx.Exec(ctx, `INSERT INTO core_server_artifacts
		(artifact_id,owner_id,account_generation,server_id,server_kind,artifact_kind,source_kind,source_id,name,status,public_url,size_bytes,metadata_json,deletion_state,created_at,updated_at)
		SELECT $1,$2,$3,agent_instance_id,'primary','static_page','static_site_release',$4,'已发布页面','published',$5,$6,
		jsonb_build_object('site_id',$7::text,'conversation_id',$8::text,'public_path',$5::text),'active',$9,$9 FROM agent_instance_metadata WHERE singleton=true
		ON CONFLICT(owner_id,account_generation,source_kind,source_id) DO NOTHING`, artifactID, command.Lease.Turn.OwnerID,
		command.Lease.Turn.AccountGeneration, command.Receipt.ReleaseID, command.Receipt.PublicPath, command.Receipt.SizeBytes,
		command.Receipt.SiteID, command.Lease.Turn.ConversationID, command.Response.Message.CreatedAt); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if err = s.commitTurnTx(ctx, tx, command.Lease, command.Response); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return core.StaticSiteReceipt{}, err
	}
	return command.Receipt, nil
}

var _ core.ConversationStaticSiteStore = (*CoreConversationStore)(nil)
