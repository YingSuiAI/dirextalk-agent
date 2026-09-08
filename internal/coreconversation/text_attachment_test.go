package coreconversation

import (
	"context"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type textAttachmentResolver struct{ content []byte }

func (r textAttachmentResolver) ResolveTurnAttachment(context.Context, Turn, TurnAttachment) ([]byte, error) {
	return append([]byte(nil), r.content...), nil
}

func TestTextAttachmentsReachModelInput(t *testing.T) {
	content := []byte("\ufeff名称,耗时\r\n刷新,12.5\r\n\"含,逗号\",2\r\n")
	for _, mediaType := range []string{"text/csv", "text/tab-separated-values", "application/json", "application/ld+json", "application/yaml", "application/xml", "text/javascript", "text/typescript", "text/x-python", "text/x-shellscript", "text/plain", "text/markdown"} {
		t.Run(mediaType, func(t *testing.T) {
			attachment := TurnAttachment{Kind: TurnAttachmentKindFile, Name: "sample.csv", MediaType: mediaType}
			turn := Turn{ID: "00000000-0000-4000-8000-000000000001", Prompt: "read the file", AttachmentSources: []TurnAttachment{attachment}}
			parts, err := resolveTurnAttachmentInputParts(context.Background(), textAttachmentResolver{content}, turn, nil)
			if err != nil || len(parts) != 1 {
				t.Fatalf("text attachment not delivered: parts=%d err=%v", len(parts), err)
			}
			for _, input := range parts {
				if len(input) != 2 || input[1].Type != coremodel.MessageInputPartText || !strings.Contains(input[1].Text, string(content)) || !strings.Contains(input[1].Text, "UNTRUSTED ATTACHMENT") {
					t.Fatalf("attachment text was changed or not bounded as untrusted: %+v", input)
				}
			}
		})
	}
}

func TestTextAttachmentDoesNotTreatBinaryAsText(t *testing.T) {
	for _, mediaType := range []string{"application/pdf", "application/zip", "application/wasm", "application/vnd.ms-excel"} {
		if IsTurnModelReadableAttachment(TurnAttachment{Kind: TurnAttachmentKindFile, MediaType: mediaType}) {
			t.Fatalf("binary %s became model text", mediaType)
		}
	}
	attachment := TurnAttachment{Kind: TurnAttachmentKindFile, Name: "bad.csv", MediaType: "text/csv"}
	for _, content := range [][]byte{{0xff, 0xfe, 1}, {'a', 0, 'b'}} {
		if err := ValidateTurnModelAttachmentContent(attachment, content); err == nil {
			t.Fatal("invalid text encoding accepted")
		}
	}
}
