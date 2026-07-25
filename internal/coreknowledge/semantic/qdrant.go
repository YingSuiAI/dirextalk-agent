package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// QdrantConfig is constructor-owned configuration. Endpoint, collection and
// dimension are never accepted from Search/Upsert requests.
type QdrantConfig struct {
	Endpoint     string
	Collection   string
	Dimension    int
	APIKey       string
	HTTPClient   *http.Client
	Timeout      time.Duration
	MaxBodyBytes int64
}

type QdrantStore struct {
	endpoint     string
	collection   string
	dimension    int
	apiKey       string
	client       *http.Client
	timeout      time.Duration
	maxBodyBytes int64
}

func NewQdrantStore(cfg QdrantConfig) (*QdrantStore, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(endpoint, "\r\n\x00") {
		return nil, ErrInvalid
	}
	if err := validateText(cfg.Collection, 256, true); err != nil || cfg.Dimension <= 0 || cfg.Dimension > 1<<20 {
		return nil, ErrInvalid
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Timeout < time.Second || cfg.Timeout > 10*time.Minute || cfg.MaxBodyBytes < 0 {
		return nil, ErrInvalid
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return &QdrantStore{endpoint: endpoint, collection: cfg.Collection, dimension: cfg.Dimension, apiKey: cfg.APIKey,
		client: cfg.HTTPClient, timeout: cfg.Timeout, maxBodyBytes: cfg.MaxBodyBytes}, nil
}

func NewQdrantHTTPStore(cfg QdrantConfig) (*QdrantStore, error) { return NewQdrantStore(cfg) }

func (q *QdrantStore) collectionPath(suffix string) string {
	return q.endpoint + "/collections/" + url.PathEscape(q.collection) + suffix
}

func (q *QdrantStore) generationCollection(generation string) string {
	return q.collection + "__stage_" + generation
}
func (q *QdrantStore) generationPath(generation, suffix string) string {
	return q.endpoint + "/collections/" + url.PathEscape(q.generationCollection(generation)) + suffix
}

func (q *QdrantStore) EnsureCollection(ctx context.Context) error {
	data, status, err := q.request(ctx, http.MethodGet, q.collectionPath(""), nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		zeroBytes(data)
		data = nil
		body := []byte(fmt.Sprintf(`{"vectors":{"size":%d,"distance":"Cosine"}}`, q.dimension))
		defer zeroBytes(body)
		_, createStatus, createErr := q.request(ctx, http.MethodPut, q.collectionPath(""), body)
		if createErr != nil {
			return createErr
		}
		if createStatus != http.StatusOK && createStatus != http.StatusCreated && createStatus != http.StatusConflict {
			return fmt.Errorf("qdrant collection create returned status %d", createStatus)
		}
		if createStatus == http.StatusConflict || createStatus == http.StatusOK || createStatus == http.StatusCreated {
			zeroBytes(data)
			data, status, err = q.request(ctx, http.MethodGet, q.collectionPath(""), nil)
			if err != nil {
				return err
			}
		}
	}
	defer zeroBytes(data)
	if status < 200 || status >= 300 {
		return fmt.Errorf("qdrant collection returned status %d", status)
	}
	if len(data) == 0 {
		return nil
	}
	var response struct {
		Result struct {
			Config struct {
				Params struct {
					Vectors struct {
						Size int `json:"size"`
					} `json:"vectors"`
				} `json:"params"`
			} `json:"config"`
		} `json:"result"`
	}
	if err := decodeBounded(data, &response); err != nil || response.Result.Config.Params.Vectors.Size != q.dimension {
		return ErrResponse
	}
	return nil
}

func (q *QdrantStore) Upsert(ctx context.Context, sourceID string, revision int64, chunks []Chunk) error {
	if err := validateUpsert(sourceID, revision, chunks, q.dimension); err != nil {
		return err
	}
	points := make([]qdrantPoint, 0, len(chunks))
	for _, chunk := range chunks {
		points = append(points, qdrantPoint{ID: PointID(sourceID, revision, chunk.Ref), Vector: append([]float32(nil), chunk.Vector...), Payload: qdrantPayload{
			SourceID: sourceID, Revision: revision, ChunkRef: chunk.Ref, Digest: chunk.Digest, Snippet: chunk.Snippet,
		}})
	}
	body, err := json.Marshal(struct {
		Points []qdrantPoint `json:"points"`
	}{Points: points})
	if err != nil {
		return ErrInvalid
	}
	defer zeroBytes(body)
	_, status, err := q.request(ctx, http.MethodPut, q.collectionPath("/points?wait=true"), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("qdrant upsert returned status %d", status)
	}
	return nil
}

func (q *QdrantStore) EnsureGeneration(ctx context.Context, generation string) error {
	if validateText(generation, 256, true) != nil {
		return ErrInvalid
	}
	data, status, err := q.request(ctx, http.MethodGet, q.generationPath(generation, ""), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		zeroBytes(data)
		return nil
	}
	zeroBytes(data)
	body := []byte(fmt.Sprintf(`{"vectors":{"size":%d,"distance":"Cosine"}}`, q.dimension))
	defer zeroBytes(body)
	_, status, err = q.request(ctx, http.MethodPut, q.generationPath(generation, ""), body)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusConflict {
		return fmt.Errorf("qdrant staging collection returned status %d", status)
	}
	return nil
}

func (q *QdrantStore) UpsertGeneration(ctx context.Context, generation, sourceID string, revision int64, chunks []Chunk) error {
	if validateText(generation, 256, true) != nil || validateUpsert(sourceID, revision, chunks, q.dimension) != nil {
		return ErrInvalid
	}
	points := make([]qdrantPoint, 0, len(chunks))
	for _, chunk := range chunks {
		points = append(points, qdrantPoint{ID: GenerationPointID(generation, sourceID, revision, chunk.Ref), Vector: append([]float32(nil), chunk.Vector...), Payload: qdrantPayload{SourceID: sourceID, Revision: revision, ChunkRef: chunk.Ref, Digest: chunk.Digest, Snippet: chunk.Snippet, Generation: generation}})
	}
	body, err := json.Marshal(struct {
		Points []qdrantPoint `json:"points"`
	}{points})
	if err != nil {
		return ErrInvalid
	}
	defer zeroBytes(body)
	_, status, err := q.request(ctx, http.MethodPut, q.generationPath(generation, "/points?wait=true"), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("qdrant staged upsert returned status %d", status)
	}
	return nil
}

func (q *QdrantStore) DeleteGeneration(ctx context.Context, generation string) error {
	if validateText(generation, 256, true) != nil {
		return ErrInvalid
	}
	_, status, err := q.request(ctx, http.MethodDelete, q.generationPath(generation, ""), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("qdrant staged delete returned status %d", status)
	}
	return nil
}
func (q *QdrantStore) DeleteStagingGeneration(ctx context.Context, generation string) error {
	return q.DeleteGeneration(ctx, generation)
}
func (q *QdrantStore) DeletePromotedGeneration(ctx context.Context, generation, sourceID string, revision int64) error {
	if validateText(generation, 256, true) != nil || validateText(sourceID, 256, true) != nil || revision <= 0 {
		return ErrInvalid
	}
	body, _ := json.Marshal(struct {
		Filter qdrantFilter `json:"filter"`
	}{qdrantFilter{Must: []qdrantCondition{{Key: "generation", Match: qdrantMatch{Value: generation}}, {Key: "source_id", Match: qdrantMatch{Value: sourceID}}, {Key: "revision", Match: qdrantMatch{Value: revision}}}}})
	defer zeroBytes(body)
	_, status, err := q.request(ctx, http.MethodPost, q.collectionPath("/points/delete?wait=true"), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("qdrant promoted delete returned status %d", status)
	}
	return nil
}

// PromoteGeneration is intentionally a validation no-op. PostgreSQL's
// promoted_generation binding is authoritative; staged collections are never
// searched by Search until that binding is committed.
func (q *QdrantStore) PromoteGeneration(ctx context.Context, generation string, bindings []Binding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil || validateBindings(bindings) != nil {
		return ErrInvalid
	}
	var cursor any
	for {
		payload := map[string]any{"limit": 1000, "with_payload": true, "with_vector": true}
		if cursor != nil {
			payload["offset"] = cursor
		}
		body, _ := json.Marshal(payload)
		data, status, err := q.request(ctx, http.MethodPost, q.generationPath(generation, "/points/scroll"), body)
		zeroBytes(body)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			zeroBytes(data)
			return fmt.Errorf("qdrant staged scroll returned status %d", status)
		}
		var resp struct {
			Result struct {
				Points []qdrantPoint `json:"points"`
				Next   any           `json:"next_page_offset"`
			} `json:"result"`
		}
		if decodeBounded(data, &resp) != nil {
			zeroBytes(data)
			return ErrResponse
		}
		zeroBytes(data)
		if len(resp.Result.Points) > 0 {
			out, _ := json.Marshal(struct {
				Points []qdrantPoint `json:"points"`
			}{resp.Result.Points})
			_, status, err = q.request(ctx, http.MethodPut, q.collectionPath("/points?wait=true"), out)
			zeroBytes(out)
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("qdrant promotion returned status %d", status)
			}
		}
		if resp.Result.Next == nil {
			return nil
		}
		cursor = resp.Result.Next
	}
}

func (q *QdrantStore) DeleteSource(ctx context.Context, sourceID string, revision int64) error {
	if validateText(sourceID, 256, true) != nil || revision <= 0 {
		return ErrInvalid
	}
	body, err := json.Marshal(struct {
		Filter qdrantFilter `json:"filter"`
	}{Filter: qdrantFilter{Must: []qdrantCondition{{Key: "source_id", Match: qdrantMatch{Value: sourceID}}, {Key: "revision", Match: qdrantMatch{Value: revision}}}}})
	if err != nil {
		return ErrInvalid
	}
	defer zeroBytes(body)
	_, status, err := q.request(ctx, http.MethodPost, q.collectionPath("/points/delete?wait=true"), body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("qdrant delete returned status %d", status)
	}
	return nil
}

func (q *QdrantStore) Search(ctx context.Context, query []float32, bindings []Binding, limit int) ([]Match, error) {
	if err := validateVector(query, q.dimension); err != nil {
		return nil, err
	}
	if err := validateBindings(bindings); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxSearchLimit {
		return nil, ErrInvalid
	}
	should := make([]qdrantNestedCondition, 0, len(bindings))
	for _, binding := range bindings {
		must := []qdrantCondition{{Key: "source_id", Match: qdrantMatch{Value: binding.SourceID}}, {Key: "revision", Match: qdrantMatch{Value: binding.Revision}}}
		if binding.Generation != "" {
			must = append(must, qdrantCondition{Key: "generation", Match: qdrantMatch{Value: binding.Generation}})
		}
		should = append(should, qdrantNestedCondition{Filter: &qdrantFilter{Must: must}})
	}
	body, err := json.Marshal(struct {
		Vector  []float32    `json:"vector"`
		Filter  qdrantFilter `json:"filter"`
		Limit   int          `json:"limit"`
		Payload bool         `json:"with_payload"`
	}{Vector: query, Filter: qdrantFilter{Should: should}, Limit: limit, Payload: true})
	if err != nil {
		return nil, ErrInvalid
	}
	defer zeroBytes(body)
	data, status, err := q.request(ctx, http.MethodPost, q.collectionPath("/points/search"), body)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("qdrant search returned status %d", status)
	}
	var response struct {
		Result []qdrantSearchResult `json:"result"`
	}
	if err := decodeBounded(data, &response); err != nil {
		return nil, ErrResponse
	}
	allowed := make(map[Binding]struct{}, len(bindings))
	for _, binding := range bindings {
		allowed[binding] = struct{}{}
	}
	matches := make([]Match, 0, len(response.Result))
	for _, item := range response.Result {
		if item.ID == "" || !isUUID(item.ID) || item.Payload.SourceID == "" || item.Payload.Revision <= 0 || item.Payload.ChunkRef == "" || item.Payload.Digest == "" {
			return nil, ErrResponse
		}
		matched := false
		for b := range allowed {
			if b.SourceID == item.Payload.SourceID && b.Revision == item.Payload.Revision && (b.Generation == "" || b.Generation == item.Payload.Generation) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrResponse
		}
		matches = append(matches, Match{SourceID: item.Payload.SourceID, Revision: item.Payload.Revision, ChunkRef: item.Payload.ChunkRef,
			Digest: item.Payload.Digest, Snippet: item.Payload.Snippet, Score: item.Score, PointID: item.ID, Generation: item.Payload.Generation})
	}
	sortMatches(matches)
	return matches, nil
}

type qdrantPoint struct {
	ID      string        `json:"id"`
	Vector  []float32     `json:"vector"`
	Payload qdrantPayload `json:"payload"`
}
type qdrantPayload struct {
	SourceID   string `json:"source_id"`
	Revision   int64  `json:"revision"`
	ChunkRef   string `json:"chunk_ref"`
	Digest     string `json:"digest"`
	Snippet    string `json:"snippet,omitempty"`
	Generation string `json:"generation"`
}
type qdrantMatch struct {
	Value any `json:"value"`
}
type qdrantCondition struct {
	Key   string      `json:"key"`
	Match qdrantMatch `json:"match"`
}
type qdrantNestedCondition struct {
	Filter *qdrantFilter `json:"filter,omitempty"`
}
type qdrantFilter struct {
	Must   []qdrantCondition       `json:"must,omitempty"`
	Should []qdrantNestedCondition `json:"should,omitempty"`
}
type qdrantSearchResult struct {
	ID      string        `json:"id"`
	Score   float32       `json:"score"`
	Payload qdrantPayload `json:"payload"`
}

func (q *QdrantStore) request(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, error) {
	callCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, ErrInvalid
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if q.apiKey != "" {
		request.Header.Set("api-key", q.apiKey)
	}
	response, err := q.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("qdrant request failed: %w", redactNetworkError(err))
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, q.maxBodyBytes+1))
	if readErr != nil {
		zeroBytes(data)
		return nil, response.StatusCode, fmt.Errorf("qdrant response read failed: %w", redactNetworkError(readErr))
	}
	if int64(len(data)) > q.maxBodyBytes {
		zeroBytes(data)
		return nil, response.StatusCode, ErrBodyTooLarge
	}
	return data, response.StatusCode, nil
}

func isUUID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

var _ VectorStore = (*QdrantStore)(nil)
