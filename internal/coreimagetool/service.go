// Package coreimagetool owns bounded, one-shot image text extraction and
// translation. Uploaded bytes never enter a conversation, task, history, or
// Capability operation request ledger.
package coreimagetool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/google/uuid"
	"golang.org/x/text/language"
)

const (
	MaxImageBytes  = 8 << 20
	MaxChunkBytes  = 1 << 20
	MaxOutputBytes = 64 << 10
	UploadTTL      = 30 * time.Minute
	ExecutionLimit = 60 * time.Second
)

var (
	ErrInvalid            = errors.New("invalid image tool request")
	ErrConflict           = errors.New("image tool request conflict")
	ErrNotFound           = errors.New("image tool source not found")
	ErrExpired            = errors.New("image tool source expired")
	ErrConsumed           = errors.New("image tool source already consumed")
	ErrDisabled           = errors.New("image tools are disabled")
	ErrModelNotConfigured = errors.New("image tool model is not configured")
	ErrModel              = errors.New("image tool model request failed")
	ErrRepository         = errors.New("image tool repository unavailable")
)

type Upload struct {
	UploadID       string    `json:"upload_id"`
	SourceID       string    `json:"source_id"`
	ImageRequestID string    `json:"image_request_id"`
	Status         string    `json:"status"`
	ReceivedSize   uint64    `json:"received_size"`
	MaxChunkBytes  uint64    `json:"max_chunk_bytes"`
	Revision       uint64    `json:"revision"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Source struct {
	SourceID       string    `json:"source_id"`
	Revision       uint64    `json:"source_revision"`
	ImageRequestID string    `json:"image_request_id"`
	Name           string    `json:"name"`
	MIMEType       string    `json:"mime_type"`
	SizeBytes      uint64    `json:"size_bytes"`
	SHA256         string    `json:"sha256"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type ConsumedSource struct {
	Source  Source
	Content []byte
}

func (s *ConsumedSource) Destroy() { clear(s.Content); s.Content = nil }

type BeginCommand struct {
	OwnerID                                        string
	AccountGeneration                              int64
	IdempotencyKey, ImageRequestID, Name, MIMEType string
	DeclaredSize                                   uint64
	ContentSHA256                                  string
}
type AppendCommand struct {
	OwnerID                  string
	AccountGeneration        int64
	IdempotencyKey, UploadID string
	ExpectedRevision         uint64
	Ordinal                  uint32
	OffsetBytes              uint64
	Data                     []byte
	ChunkSHA256              string
}

func (c *AppendCommand) Destroy() { clear(c.Data); c.Data = nil }

type CommitCommand struct {
	OwnerID                  string
	AccountGeneration        int64
	IdempotencyKey, UploadID string
	ExpectedRevision         uint64
	ContentSHA256            string
}
type ConsumeCommand struct {
	OwnerID                  string
	AccountGeneration        int64
	ImageRequestID, SourceID string
	SourceRevision           uint64
}

type Repository interface {
	Begin(context.Context, BeginCommand) (Upload, error)
	Append(context.Context, AppendCommand) (Upload, error)
	Commit(context.Context, CommitCommand) (Source, error)
	Consume(context.Context, ConsumeCommand) (ConsumedSource, error)
}
type ModelResolver interface {
	ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error)
}
type TextToolConfig interface {
	Get(context.Context, string, int64) (coretexttool.Config, error)
}
type ClientFactory func(coremodel.Profile) (coremodel.Client, error)

type Service struct {
	repository Repository
	configs    TextToolConfig
	models     ModelResolver
	client     ClientFactory
}

func NewService(repository Repository, configs TextToolConfig, models ModelResolver, client ClientFactory) (*Service, error) {
	if repository == nil || configs == nil || models == nil || client == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, configs: configs, models: models, client: client}, nil
}
func (s *Service) Begin(ctx context.Context, c BeginCommand) (Upload, error) {
	if !validBegin(c) {
		return Upload{}, ErrInvalid
	}
	v, e := s.repository.Begin(ctx, c)
	return v, safe(e)
}
func (s *Service) Append(ctx context.Context, c AppendCommand) (Upload, error) {
	defer c.Destroy()
	if !validAppend(c) {
		return Upload{}, ErrInvalid
	}
	v, e := s.repository.Append(ctx, c)
	return v, safe(e)
}
func (s *Service) Commit(ctx context.Context, c CommitCommand) (Source, error) {
	if !validCommit(c) {
		return Source{}, ErrInvalid
	}
	v, e := s.repository.Commit(ctx, c)
	return v, safe(e)
}

type ExecuteCommand struct {
	OwnerID                  string
	AccountGeneration        int64
	IdempotencyKey, SourceID string
	SourceRevision           uint64
	TargetLocale             string
}
type ExecuteResult struct {
	IdempotencyKey string `json:"idempotency_key"`
	SourceID       string `json:"source_id"`
	SourceRevision uint64 `json:"source_revision"`
	Text           string `json:"text"`
	TargetLocale   string `json:"target_locale,omitempty"`
}

func (s *Service) ExtractText(ctx context.Context, c ExecuteCommand) (ExecuteResult, error) {
	return s.execute(ctx, c, "Extract all visible text from this image faithfully. Preserve reading order, paragraphs, line breaks, punctuation, names, and numbers. Return only the extracted text. If no text is visible, return an empty response.", false)
}
func (s *Service) TranslateText(ctx context.Context, c ExecuteCommand) (ExecuteResult, error) {
	if !validLocale(c.TargetLocale) {
		return ExecuteResult{}, ErrInvalid
	}
	prompt := "Extract all visible text from this image and translate it faithfully into " + c.TargetLocale + ". Preserve reading order, paragraphs, line breaks, punctuation, names, and numbers. Return only the translation. If no text is visible, return an empty response."
	return s.execute(ctx, c, prompt, true)
}
func (s *Service) execute(ctx context.Context, c ExecuteCommand, prompt string, translate bool) (ExecuteResult, error) {
	originalKey, originalSource := c.IdempotencyKey, c.SourceID
	c.OwnerID = strings.TrimSpace(c.OwnerID)
	c.SourceID = strings.TrimSpace(c.SourceID)
	c.IdempotencyKey = strings.TrimSpace(c.IdempotencyKey)
	if !validIdentity(c.OwnerID, c.AccountGeneration) || !canonicalUUID(c.IdempotencyKey) || !canonicalUUID(c.SourceID) || c.SourceRevision != 1 {
		return ExecuteResult{}, ErrInvalid
	}
	if c.IdempotencyKey != originalKey || c.SourceID != originalSource {
		return ExecuteResult{}, ErrInvalid
	}
	config, err := s.configs.Get(ctx, c.OwnerID, c.AccountGeneration)
	if err != nil {
		return ExecuteResult{}, safe(err)
	}
	if !config.Enabled {
		return ExecuteResult{}, ErrDisabled
	}
	profile, err := s.models.ResolveDefaultToolProfile(ctx)
	if err != nil {
		return ExecuteResult{}, errors.Join(ErrModelNotConfigured, err)
	}
	defer func() {
		profile.APIKey = ""
		for k := range profile.ProviderSecrets {
			profile.ProviderSecrets[k] = ""
			delete(profile.ProviderSecrets, k)
		}
	}()
	if strings.TrimSpace(profile.ModelKind) != coremodel.ModelKindConversation || !hasImage(profile.InputModalities) || profile.Revision <= 0 || profile.CredentialVersion <= 0 || strings.TrimSpace(profile.APIKey) == "" {
		return ExecuteResult{}, ErrModelNotConfigured
	}
	source, err := s.repository.Consume(ctx, ConsumeCommand{OwnerID: c.OwnerID, AccountGeneration: c.AccountGeneration, ImageRequestID: c.IdempotencyKey, SourceID: c.SourceID, SourceRevision: c.SourceRevision})
	if err != nil {
		return ExecuteResult{}, safe(err)
	}
	defer source.Destroy()
	client, err := s.client(profile)
	if err != nil {
		return ExecuteResult{}, errors.Join(ErrModel, err)
	}
	ctx, cancel := context.WithTimeout(ctx, ExecutionLimit)
	defer cancel()
	image := coremodel.NewImageInput(source.Source.MIMEType, source.Content)
	defer image.Destroy()
	completion, err := client.Generate(ctx, coremodel.CompletionRequest{Messages: []coremodel.Message{{Role: coremodel.RoleUser, InputParts: []coremodel.MessageInputPart{{Type: coremodel.MessageInputPartText, Text: prompt}, {Type: coremodel.MessageInputPartImage, Image: image}}}}})
	if err != nil {
		return ExecuteResult{}, errors.Join(ErrModel, err)
	}
	text := strings.TrimSpace(completion.Message.Content)
	if !utf8.ValidString(text) || len(text) > MaxOutputBytes {
		return ExecuteResult{}, ErrModel
	}
	result := ExecuteResult{IdempotencyKey: c.IdempotencyKey, SourceID: c.SourceID, SourceRevision: c.SourceRevision, Text: text}
	if translate {
		result.TargetLocale = c.TargetLocale
	}
	return result, nil
}

func validIdentity(o string, g int64) bool {
	return strings.TrimSpace(o) != "" && len(strings.TrimSpace(o)) <= 512 && g > 0
}
func canonicalUUID(v string) bool {
	p, e := uuid.Parse(v)
	return e == nil && p != uuid.Nil && p.String() == v
}
func validMIME(v string) bool { return v == "image/jpeg" || v == "image/png" || v == "image/webp" }
func validSHA(v string) bool {
	if len(v) != 64 || v != strings.ToLower(v) {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func validName(v string) bool {
	return utf8.ValidString(v) && strings.TrimSpace(v) != "" && len(v) <= 255 && !strings.ContainsAny(v, "\x00\r\n")
}
func validBegin(c BeginCommand) bool {
	return validIdentity(c.OwnerID, c.AccountGeneration) && canonicalUUID(c.IdempotencyKey) && canonicalUUID(c.ImageRequestID) && validName(c.Name) && validMIME(c.MIMEType) && c.DeclaredSize > 0 && c.DeclaredSize <= MaxImageBytes && validSHA(c.ContentSHA256)
}
func validAppend(c AppendCommand) bool {
	if !validIdentity(c.OwnerID, c.AccountGeneration) || !canonicalUUID(c.IdempotencyKey) || !canonicalUUID(c.UploadID) || c.ExpectedRevision == 0 || len(c.Data) == 0 || len(c.Data) > MaxChunkBytes || !validSHA(c.ChunkSHA256) {
		return false
	}
	d := sha256.Sum256(c.Data)
	return hex.EncodeToString(d[:]) == c.ChunkSHA256
}
func validCommit(c CommitCommand) bool {
	return validIdentity(c.OwnerID, c.AccountGeneration) && canonicalUUID(c.IdempotencyKey) && canonicalUUID(c.UploadID) && c.ExpectedRevision > 0 && validSHA(c.ContentSHA256)
}
func validLocale(v string) bool {
	if strings.TrimSpace(v) != v || v == "" || len(v) > 64 || strings.Contains(v, "_") {
		return false
	}
	t, e := language.Parse(v)
	return e == nil && t.String() == v
}
func hasImage(v []string) bool {
	for _, x := range v {
		if strings.TrimSpace(x) == "image" {
			return true
		}
	}
	return false
}
func safe(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrInvalid, ErrConflict, ErrNotFound, ErrExpired, ErrConsumed, ErrDisabled, ErrModelNotConfigured, ErrModel, ErrRepository} {
		if errors.Is(err, known) {
			return err
		}
	}
	if errors.Is(err, coretexttool.ErrDisabled) {
		return ErrDisabled
	}
	return ErrRepository
}
