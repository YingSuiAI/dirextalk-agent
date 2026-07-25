package coreknowledge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

type ParsedChunk struct {
	Ref  string
	Text string
}

// ParseV1 deterministically parses bounded text/plain, text/markdown and JSON.
func ParseV1(ctx context.Context, mediaType string, input io.Reader, maxBytes int64) ([]ParsedChunk, error) {
	if ctx == nil || input == nil || maxBytes < 1 {
		return nil, ErrInvalid
	}
	mediaType = strings.ToLower(strings.TrimSpace(strings.Split(mediaType, ";")[0]))
	if mediaType != "text/plain" && mediaType != "text/markdown" && mediaType != "application/json" {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return nil, ErrConflict
	}
	if int64(len(b)) > maxBytes || !utf8.Valid(b) {
		return nil, ErrLimitExceeded
	}
	if mediaType == "application/json" && !json.Valid(b) {
		return nil, errors.New("invalid json")
	}
	const chunkBytes = 4096
	var out []ParsedChunk
	for len(b) > 0 {
		n := chunkBytes
		if len(b) < n {
			n = len(b)
		}
		for n > 0 && n < len(b) && !utf8.Valid(b[:n]) {
			n--
		}
		if n == 0 {
			return nil, ErrInvalid
		}
		out = append(out, ParsedChunk{Ref: "chunk-" + fmtChunk(len(out)), Text: string(b[:n])})
		b = b[n:]
	}
	return out, nil
}

func fmtChunk(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "000000"
	}
	var b [6]byte
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[:])
}
