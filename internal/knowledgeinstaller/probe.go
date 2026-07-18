package installer

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	probeMemoryID  = "91b749a1-133f-4b4e-9481-8b4655aad290"
	probeRevision  = "35e1e7e5-d476-4720-9b17-05690ecef520"
	probeOwnerID   = "owner:semantic-probe"
	probeBindingID = "d4bc902d-b728-4d4e-ab72-bcefb3eec8c9"
	probeDigest    = "3a564f59a7ebf95f51dc5287a7ba6c73bb75e4f16aae3690a01bac3d9e1ea837"
	probePointID   = "eb886927-4108-5556-9f64-9c883de47203"
)

type RoundTripper interface {
	RoundTrip(context.Context, map[string]any) (map[string]any, error)
}

type UnixRoundTripper struct {
	Socket string
}

func (u UnixRoundTripper) RoundTrip(ctx context.Context, request map[string]any) (map[string]any, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", u.Socket)
	if err != nil {
		return nil, fmt.Errorf("connect fixed adapter socket: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set adapter deadline: %w", err)
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > 262_144 {
		return nil, fmt.Errorf("encode fixed semantic probe")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	frame := append(header[:], payload...)
	if err := writeAll(connection, frame); err != nil {
		return nil, fmt.Errorf("write fixed semantic probe: %w", err)
	}
	reader := bufio.NewReader(connection)
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("read semantic probe header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 1_048_576 {
		return nil, fmt.Errorf("semantic probe response exceeds bound")
	}
	responsePayload := make([]byte, length)
	if _, err := io.ReadFull(reader, responsePayload); err != nil {
		return nil, fmt.Errorf("read semantic probe response: %w", err)
	}
	var response map[string]any
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		return nil, fmt.Errorf("decode semantic probe response: %w", err)
	}
	return response, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func SemanticProbeV1(ctx context.Context, client RoundTripper) error {
	requests := []map[string]any{
		{
			"version": 1, "operation_id": "99c5df5f-0786-46f8-bd17-99d6df701660",
			"idempotency_key": "c00f0c6b-cd41-4a38-98c0-c8afb254b98d", "operation": "store_memory",
			"body": map[string]any{
				"owner_id": probeOwnerID, "binding_id": probeBindingID, "memory_id": probeMemoryID,
				"revision_id": probeRevision, "content": "dirextalk retained knowledge semantic probe cedar",
				"content_size": 49, "content_sha256": probeDigest,
			},
		},
		{
			"version": 1, "operation_id": "4b5505b4-80b2-47ba-91a8-2dd4693e1cba", "operation": "search",
			"body": map[string]any{
				"owner_id": probeOwnerID, "binding_id": probeBindingID, "query": "retained semantic probe cedar",
				"limit": 5, "source_ids": []string{probeMemoryID},
			},
		},
		{
			"version": 1, "operation_id": "fbbf1564-4c4c-4d91-b88b-33e03437e674", "operation": "status",
			"body": map[string]any{
				"owner_id": probeOwnerID, "binding_id": probeBindingID,
				"challenge": map[string]any{
					"point_id": probeMemoryID, "source_id": probeMemoryID, "revision_id": probeRevision,
					"content_size": 49, "content_sha256": probeDigest,
				},
			},
		},
	}
	pointID := ""
	for index, request := range requests {
		if index == 2 {
			challenge := request["body"].(map[string]any)["challenge"].(map[string]any)
			challenge["point_id"] = pointID
		}
		response, err := client.RoundTrip(ctx, request)
		if err != nil {
			return err
		}
		if response["ok"] != true || response["operation_id"] != request["operation_id"] {
			return fmt.Errorf("semantic probe operation %d failed", index+1)
		}
		result, ok := response["result"].(map[string]any)
		if !ok {
			return fmt.Errorf("semantic probe operation %d returned no result", index+1)
		}
		switch index {
		case 0:
			var ok bool
			pointID, ok = result["point_id"].(string)
			if !ok || !isCanonicalUUID(pointID) || !positiveBoundedCount(result["indexed_segment_count"], 512) ||
				result["owner_id"] != probeOwnerID || result["binding_id"] != probeBindingID ||
				result["source_id"] != probeMemoryID || result["revision_id"] != probeRevision ||
				!exactJSONInteger(result["content_size"], 49) || result["content_sha256"] != probeDigest {
				return fmt.Errorf("semantic probe mutation binding mismatch")
			}
		case 1:
			values, ok := result["results"].([]any)
			if !ok || !containsProbeMemory(values, pointID) {
				return fmt.Errorf("semantic probe search did not find fixed memory")
			}
		case 2:
			persistence, ok := result["persistence"].(map[string]any)
			status, statusOK := result["status"].(string)
			if !ok || result["owner_id"] != probeOwnerID || result["binding_id"] != probeBindingID || result["ready"] != true ||
				result["model"] != "intfloat/multilingual-e5-small" || result["model_revision"] != ModelRevision ||
				!exactJSONInteger(result["dimensions"], 384) || result["execution_provider"] != "CPUExecutionProvider" ||
				result["collection"] != "dirextalk_knowledge_v1" || !statusOK || (status != "green" && status != "yellow") ||
				persistence["verified"] != true || persistence["point_id"] != pointID || persistence["source_id"] != probeMemoryID ||
				persistence["revision_id"] != probeRevision || !exactJSONInteger(persistence["content_size"], 49) || persistence["content_sha256"] != probeDigest {
				return fmt.Errorf("semantic probe persistence challenge failed")
			}
		}
	}
	return nil
}

func exactJSONInteger(value any, expected int) bool {
	switch number := value.(type) {
	case int:
		return number == expected
	case float64:
		return number == float64(expected)
	default:
		return false
	}
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return value != "00000000-0000-0000-0000-000000000000" && strings.Contains("89ab", value[19:20])
}

func positiveBoundedCount(value any, maximum int) bool {
	switch count := value.(type) {
	case int:
		return count >= 1 && count <= maximum
	case float64:
		return count >= 1 && count <= float64(maximum) && count == float64(int(count))
	default:
		return false
	}
}

func containsProbeMemory(values []any, pointID string) bool {
	for _, value := range values {
		result, ok := value.(map[string]any)
		if ok && result["point_id"] == pointID && result["owner_id"] == probeOwnerID && result["binding_id"] == probeBindingID &&
			result["source_id"] == probeMemoryID && result["revision_id"] == probeRevision && result["kind"] == "memory" &&
			exactJSONInteger(result["content_size"], 49) && result["content_sha256"] == probeDigest {
			return true
		}
	}
	return false
}
