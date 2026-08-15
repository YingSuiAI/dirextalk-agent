package coreconversation

import (
	"context"
	"mime"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
)

const (
	MaxTurnAttachments          = 4
	MaxTurnAttachmentBytes      = 8 << 20
	MaxTurnAttachmentsBytes     = 8 << 20
	MaxTurnAttachmentChunkBytes = 1 << 20
	MaxTurnAttachmentNameBytes  = 255
	TurnAttachmentUploadTTL     = 30 * time.Minute
)

const (
	TurnAttachmentKindImage            = "image"
	TurnAttachmentKindFile             = "file"
	TurnAttachmentKindWorkspaceArchive = "workspace_archive"
)

type TurnAttachmentStatus string

const (
	TurnAttachmentReceiving TurnAttachmentStatus = "receiving"
	TurnAttachmentCommitted TurnAttachmentStatus = "committed"
	TurnAttachmentConsumed  TurnAttachmentStatus = "consumed"
)

// TurnAttachment is the immutable, secret-free source metadata accepted with
// a durable turn. Content is kept in the source authority and is never copied
// into turn JSON, model transcript, capability results, or logs.
type TurnAttachment struct {
	SourceID      string               `json:"source_id"`
	Revision      uint64               `json:"revision"`
	TurnRequestID string               `json:"turn_request_id"`
	Kind          string               `json:"kind"`
	Name          string               `json:"name"`
	MediaType     string               `json:"mime_type"`
	SizeBytes     uint64               `json:"size_bytes"`
	SHA256        string               `json:"sha256"`
	Status        TurnAttachmentStatus `json:"status"`
	ExpiresAt     time.Time            `json:"expires_at"`
}

func (attachment TurnAttachment) Validate() error {
	if !validUUID(attachment.SourceID) || attachment.Revision != 1 ||
		!validUUID(attachment.TurnRequestID) || !ValidTurnAttachmentKind(attachment.Kind) ||
		!ValidTurnAttachmentName(attachment.Name) || !ValidTurnAttachmentMediaType(attachment.Kind, attachment.MediaType) ||
		attachment.SizeBytes == 0 || attachment.SizeBytes > MaxTurnAttachmentBytes ||
		len(attachment.SHA256) != 64 || attachment.Status != TurnAttachmentCommitted ||
		attachment.ExpiresAt.IsZero() || attachment.ExpiresAt != attachment.ExpiresAt.UTC() {
		return ErrInvalid
	}
	for _, value := range attachment.SHA256 {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return ErrInvalid
		}
	}
	return nil
}

type TurnAttachmentUpload struct {
	UploadID      string               `json:"upload_id"`
	SourceID      string               `json:"source_id"`
	TurnRequestID string               `json:"turn_request_id"`
	Status        TurnAttachmentStatus `json:"status"`
	ReceivedSize  uint64               `json:"received_size"`
	MaxChunkBytes uint64               `json:"max_chunk_bytes"`
	Revision      uint64               `json:"revision"`
	ExpiresAt     time.Time            `json:"expires_at"`
}

type BeginTurnAttachmentUploadCommand struct {
	OwnerID           string
	AccountGeneration uint64
	IdempotencyKey    string
	TurnRequestID     string
	Kind              string
	Name              string
	MediaType         string
	DeclaredSize      uint64
	ContentSHA256     string
}

type AppendTurnAttachmentUploadCommand struct {
	OwnerID           string
	AccountGeneration uint64
	IdempotencyKey    string
	UploadID          string
	ExpectedRevision  uint64
	Ordinal           uint32
	OffsetBytes       uint64
	Data              []byte
	ChunkSHA256       string
}

func (command *AppendTurnAttachmentUploadCommand) Destroy() {
	if command == nil {
		return
	}
	clear(command.Data)
	*command = AppendTurnAttachmentUploadCommand{}
}

type CommitTurnAttachmentUploadCommand struct {
	OwnerID           string
	AccountGeneration uint64
	IdempotencyKey    string
	UploadID          string
	ExpectedRevision  uint64
	ContentSHA256     string
}

type TurnAttachmentUploadStore interface {
	BeginTurnAttachmentUpload(context.Context, BeginTurnAttachmentUploadCommand) (TurnAttachmentUpload, error)
	AppendTurnAttachmentUpload(context.Context, AppendTurnAttachmentUploadCommand) (TurnAttachmentUpload, error)
	CommitTurnAttachmentUpload(context.Context, CommitTurnAttachmentUploadCommand) (TurnAttachment, error)
}

func ValidateAcceptedTurnAttachments(requestID string, acceptedIDs []string, attachments []TurnAttachment) error {
	if !validUUID(requestID) || len(acceptedIDs) > MaxTurnAttachments || len(attachments) != len(acceptedIDs) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(acceptedIDs))
	var total uint64
	archiveCount := 0
	for index, id := range acceptedIDs {
		if !validUUID(id) || attachments[index].Validate() != nil || attachments[index].SourceID != id ||
			attachments[index].TurnRequestID != requestID {
			return ErrInvalid
		}
		if _, duplicate := seen[id]; duplicate {
			return ErrConflict
		}
		seen[id] = struct{}{}
		if attachments[index].Kind == TurnAttachmentKindWorkspaceArchive {
			archiveCount++
			if archiveCount > 1 {
				return ErrInvalid
			}
		}
		total += attachments[index].SizeBytes
		if total > MaxTurnAttachmentsBytes {
			return ErrInvalid
		}
	}
	return nil
}

func TurnAttachmentSnapshotDigest(values []TurnAttachment) string {
	if len(values) == 0 {
		return ""
	}
	return digest(turnMustJSON(values))
}

func ValidTurnAttachmentName(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= MaxTurnAttachmentNameBytes &&
		utf8.ValidString(value) && path.Base(value) == value && value != "." && value != ".." &&
		!strings.ContainsAny(value, "\\/\r\n\x00")
}

func ValidTurnAttachmentKind(value string) bool {
	return value == TurnAttachmentKindImage || value == TurnAttachmentKindFile ||
		value == TurnAttachmentKindWorkspaceArchive
}

func ValidTurnAttachmentMediaType(kind, value string) bool {
	if value != strings.ToLower(strings.TrimSpace(value)) {
		return false
	}
	parsed, parameters, err := mime.ParseMediaType(value)
	if err != nil || parsed != value || len(parameters) != 0 {
		return false
	}
	switch kind {
	case TurnAttachmentKindImage:
		return value == "image/jpeg" || value == "image/png" || value == "image/webp"
	case TurnAttachmentKindWorkspaceArchive:
		return value == workspacearchive.MediaType
	case TurnAttachmentKindFile:
		if strings.HasPrefix(value, "text/") {
			return true
		}
		switch value {
		case "application/json", "application/ld+json", "application/xml", "application/yaml",
			"application/pdf", "application/rtf", "application/octet-stream", "application/wasm",
			"application/zip", "application/msword", "application/vnd.ms-excel",
			"application/vnd.ms-powerpoint",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			"application/vnd.openxmlformats-officedocument.presentationml.presentation":
			return true
		}
		if strings.HasSuffix(value, "+json") || strings.HasSuffix(value, "+xml") {
			return true
		}
		return false
	default:
		return false
	}
}

func IsTurnModelReadableAttachment(attachment TurnAttachment) bool {
	return attachment.Kind == TurnAttachmentKindImage ||
		(attachment.Kind == TurnAttachmentKindFile && (attachment.MediaType == "text/plain" || attachment.MediaType == "text/markdown"))
}

func ValidateTurnModelAttachmentContent(attachment TurnAttachment, content []byte) error {
	if !IsTurnModelReadableAttachment(attachment) {
		return ErrInvalid
	}
	if attachment.Kind == TurnAttachmentKindFile && !utf8.Valid(content) {
		return ErrInvalid
	}
	return nil
}
