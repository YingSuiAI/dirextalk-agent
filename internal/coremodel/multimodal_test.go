package coremodel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func multimodalRequest(mime string, data []byte) CompletionRequest {
	return CompletionRequest{Messages: []Message{{Role: RoleUser, InputParts: []MessageInputPart{
		{Type: MessageInputPartText, Text: "Read this image"},
		{Type: MessageInputPartImage, Image: NewImageInput(mime, data)},
	}}}}
}

func TestProviderMultimodalPayloads(t *testing.T) {
	data := []byte{0xff, 0xd8, 0x01}
	encoded := base64.StdEncoding.EncodeToString(data)

	openAI, err := json.Marshal(openAIPayload(validProfile(ProviderOpenAICompatible, "https://example.test", "k"), multimodalRequest("image/jpeg", data), false))
	if err != nil {
		t.Fatal(err)
	}
	wantOpenAI := `"content":[{"text":"Read this image","type":"text"},{"image_url":{"url":"data:image/jpeg;base64,` + encoded + `"},"type":"image_url"}]`
	if !strings.Contains(string(openAI), wantOpenAI) {
		t.Fatalf("OpenAI typed content mismatch: %s", openAI)
	}

	anthropic, err := json.Marshal(anthropicPayload(validProfile(ProviderAnthropic, "https://example.test", "k"), multimodalRequest("image/png", data), false))
	if err != nil {
		t.Fatal(err)
	}
	wantAnthropic := `"content":[{"text":"Read this image","type":"text"},{"source":{"data":"` + encoded + `","media_type":"image/png","type":"base64"},"type":"image"}]`
	if !strings.Contains(string(anthropic), wantAnthropic) {
		t.Fatalf("Anthropic typed content mismatch: %s", anthropic)
	}

	gemini, err := json.Marshal(geminiPayload(validProfile(ProviderGemini, "https://example.test", "k"), multimodalRequest("image/webp", data)))
	if err != nil {
		t.Fatal(err)
	}
	wantGemini := `"parts":[{"text":"Read this image"},{"inlineData":{"data":"` + encoded + `","mimeType":"image/webp"}}]`
	if !strings.Contains(string(gemini), wantGemini) {
		t.Fatalf("Gemini typed content mismatch: %s", gemini)
	}
}

func TestEveryProviderAcceptsSupportedImageMIMETypes(t *testing.T) {
	providers := []ModelProvider{ProviderOpenAICompatible, ProviderAnthropic, ProviderGemini}
	for _, provider := range providers {
		for _, mime := range []string{"image/jpeg", "image/png", "image/webp"} {
			t.Run(string(provider)+"/"+mime, func(t *testing.T) {
				request := multimodalRequest(mime, []byte("image"))
				if err := ValidateCompletionRequest(request); err != nil {
					t.Fatal(err)
				}
				var payload any
				switch provider {
				case ProviderAnthropic:
					payload = anthropicPayload(validProfile(provider, "https://example.test", "k"), request, false)
				case ProviderGemini:
					payload = geminiPayload(validProfile(provider, "https://example.test", "k"), request)
				default:
					payload = openAIPayload(validProfile(provider, "https://example.test", "k"), request, false)
				}
				encoded, err := json.Marshal(payload)
				if err != nil || !strings.Contains(string(encoded), mime) || !strings.Contains(string(encoded), base64.StdEncoding.EncodeToString([]byte("image"))) {
					t.Fatalf("payload=%s err=%v", encoded, err)
				}
			})
		}
	}
}

func TestMultimodalValidationRejectsInvalidShapeMIMEAndSize(t *testing.T) {
	cases := map[string]CompletionRequest{
		"assistant image": {Messages: []Message{{Role: RoleAssistant, InputParts: multimodalRequest("image/png", []byte("x")).Messages[0].InputParts}}},
		"no prompt":       {Messages: []Message{{Role: RoleUser, InputParts: []MessageInputPart{{Type: MessageInputPartImage, Image: NewImageInput("image/png", []byte("x"))}}}}},
		"invalid mime":    multimodalRequest("image/gif", []byte("x")),
		"empty image":     multimodalRequest("image/png", nil),
		"oversize":        multimodalRequest("image/png", make([]byte, maxImageInputBytes+1)),
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateCompletionRequest(request); err == nil {
				t.Fatal("accepted invalid multimodal request")
			}
		})
	}
}

func TestEinoMultimodalRoundTripAndRejectsExternalImageReferences(t *testing.T) {
	original := multimodalRequest("image/png", []byte("private-image")).Messages[0]
	converted, err := fromEinoMessages([]*schema.Message{toEinoMessage(original)})
	if err != nil || len(converted) != 1 || len(converted[0].InputParts) != 2 {
		t.Fatalf("round trip=%#v err=%v", converted, err)
	}
	if got := converted[0].InputParts[1].Image.Bytes(); string(got) != "private-image" {
		t.Fatalf("image bytes changed: %q", got)
	}

	for _, external := range []string{"https://example.test/image.png", "data:image/png;base64,eA==", "/tmp/image.png"} {
		t.Run(external, func(t *testing.T) {
			message := &schema.Message{Role: schema.User, UserInputMultiContent: []schema.MessageInputPart{
				{Type: schema.ChatMessagePartTypeText, Text: "read"},
				{Type: schema.ChatMessagePartTypeImageURL, Image: &schema.MessageInputImage{MessagePartCommon: schema.MessagePartCommon{URL: &external, MIMEType: "image/png"}}},
			}}
			if _, err := fromEinoMessages([]*schema.Message{message}); !errors.Is(err, ErrInvalidCompletionRequest) {
				t.Fatalf("external reference error=%v", err)
			}
		})
	}
}

func TestMultimodalBudgetDoesNotBroadenPlainTextRequests(t *testing.T) {
	plain := CompletionRequest{Messages: []Message{{Role: RoleUser, Content: strings.Repeat("x", 1<<20)}, {Role: RoleUser, Content: strings.Repeat("y", 1<<20)}}}
	if !errors.Is(ValidateCompletionRequest(plain), ErrCompletionRequestTooLarge) {
		t.Fatal("plain text request escaped the existing 2 MiB budget")
	}
	request := multimodalRequest("image/png", make([]byte, maxImageInputBytes))
	if err := ValidateCompletionRequest(request); err != nil {
		t.Fatalf("valid 8 MiB image rejected: %v", err)
	}
}

func TestImageBytesAreRedactedFromJSONAndFormatting(t *testing.T) {
	const secret = "DO_NOT_LEAK_IMAGE_BYTES"
	message := multimodalRequest("image/png", []byte(secret)).Messages[0]
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"json": string(encoded), "string": fmt.Sprintf("%v", message), "go_string": fmt.Sprintf("%#v", message)} {
		if strings.Contains(value, secret) {
			t.Fatalf("%s leaked image bytes: %s", name, value)
		}
	}
}

func TestImageInputDestroyClearsOwnedBytesAndMetadata(t *testing.T) {
	source := []byte("private-image")
	image := NewImageInput("image/png", source)
	image.Destroy()
	image.Destroy()

	if got := image.Bytes(); len(got) != 0 {
		t.Fatalf("destroyed image retained %d bytes", len(got))
	}
	if image.MIMEType != "" {
		t.Fatalf("destroyed image retained MIME type %q", image.MIMEType)
	}
	if string(source) != "private-image" {
		t.Fatalf("destroy modified caller-owned source: %q", source)
	}
}
