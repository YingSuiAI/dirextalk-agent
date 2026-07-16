package awsprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

const maxCredentialPayload = 64 * 1024

var (
	ErrInvalidCredentials = errors.New("invalid AWS bootstrap credentials")
	ErrCredentialRejected = errors.New("AWS bootstrap credentials were rejected")
	accessKeyPattern      = regexp.MustCompile(`^(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}$`)
)

// Credentials owns mutable credential buffers. Callers must invoke Wipe as
// soon as an SDK credential provider has copied the values it needs.
type Credentials struct {
	AccessKeyID     []byte
	SecretAccessKey []byte
	SessionToken    []byte
}

func (credentials *Credentials) Wipe() {
	if credentials == nil {
		return
	}
	secretbootstrap.Wipe(credentials.AccessKeyID)
	secretbootstrap.Wipe(credentials.SecretAccessKey)
	secretbootstrap.Wipe(credentials.SessionToken)
	credentials.AccessKeyID = nil
	credentials.SecretAccessKey = nil
	credentials.SessionToken = nil
}

func (credentials Credentials) valid() bool {
	return accessKeyPattern.Match(credentials.AccessKeyID) &&
		len(credentials.SecretAccessKey) >= 20 && len(credentials.SecretAccessKey) <= 128 &&
		len(credentials.SessionToken) <= 16*1024 &&
		!bytes.ContainsAny(credentials.AccessKeyID, "\r\n\x00") &&
		!bytes.ContainsAny(credentials.SecretAccessKey, "\r\n\x00") &&
		!bytes.ContainsAny(credentials.SessionToken, "\r\n\x00")
}

// ConsumeBootstrapCredentials parses one uploaded AWS CSV or JSON credential
// payload and guarantees best-effort wiping of both the caller-owned payload
// and parsed credential buffers. Consumer errors are deliberately redacted:
// an AWS SDK error is allowed to contain request details internally but must
// never become a user-facing secret oracle.
func ConsumeBootstrapCredentials(payload []byte, consumer func(*Credentials) error) error {
	defer secretbootstrap.Wipe(payload)
	if len(payload) == 0 || len(payload) > maxCredentialPayload || consumer == nil {
		return ErrInvalidCredentials
	}
	credentials, err := parseCredentials(payload)
	if err != nil {
		return ErrInvalidCredentials
	}
	defer credentials.Wipe()
	if err := consumer(&credentials); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrInvalidCredentials
		}
		return ErrCredentialRejected
	}
	return nil
}

func parseCredentials(payload []byte) (Credentials, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return Credentials{}, ErrInvalidCredentials
	}
	var credentials Credentials
	var err error
	if trimmed[0] == '{' {
		credentials, err = parseJSONCredentials(trimmed)
	} else {
		credentials, err = parseCSVCredentials(trimmed)
	}
	if err != nil || !credentials.valid() {
		credentials.Wipe()
		return Credentials{}, ErrInvalidCredentials
	}
	return credentials, nil
}

func parseJSONCredentials(payload []byte) (Credentials, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return Credentials{}, err
	}
	values := make(map[string][]byte, 3)
	defer func() {
		for _, value := range values {
			secretbootstrap.Wipe(value)
		}
	}()
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || (key != "AccessKeyId" && key != "SecretAccessKey" && key != "SessionToken") {
			return Credentials{}, ErrInvalidCredentials
		}
		if _, duplicate := values[key]; duplicate {
			return Credentials{}, ErrInvalidCredentials
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			secretbootstrap.Wipe(raw)
			return Credentials{}, err
		}
		decoded, err := strictASCIIJSONString(raw)
		secretbootstrap.Wipe(raw)
		if err != nil {
			return Credentials{}, err
		}
		values[key] = decoded
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || ensureJSONEOF(decoder) != nil {
		return Credentials{}, ErrInvalidCredentials
	}
	return Credentials{
		AccessKeyID:     append([]byte(nil), values["AccessKeyId"]...),
		SecretAccessKey: append([]byte(nil), values["SecretAccessKey"]...),
		SessionToken:    append([]byte(nil), values["SessionToken"]...),
	}, nil
}

func strictASCIIJSONString(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, ErrInvalidCredentials
	}
	result := append([]byte(nil), raw[1:len(raw)-1]...)
	for _, value := range result {
		if value < 0x20 || value > 0x7e || value == '\\' || value == '"' {
			secretbootstrap.Wipe(result)
			return nil, ErrInvalidCredentials
		}
	}
	return result, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrInvalidCredentials
}

func parseCSVCredentials(payload []byte) (Credentials, error) {
	records, err := parseCSVBytes(payload)
	if err != nil {
		return Credentials{}, ErrInvalidCredentials
	}
	defer wipeCSVRecords(records)
	if len(records) != 2 || len(records[0]) < 2 || len(records[0]) != len(records[1]) {
		return Credentials{}, ErrInvalidCredentials
	}

	allowed := map[string]bool{
		"user name":          true,
		"access key id":      true,
		"secret access key":  true,
		"session token":      true,
		"console login link": true,
	}
	indexes := make(map[string]int, len(records[0]))
	for index, rawHeader := range records[0] {
		header := string(bytes.ToLower(bytes.TrimSpace(rawHeader)))
		if !allowed[header] {
			return Credentials{}, ErrInvalidCredentials
		}
		if _, duplicate := indexes[header]; duplicate {
			return Credentials{}, ErrInvalidCredentials
		}
		indexes[header] = index
	}
	accessIndex, accessOK := indexes["access key id"]
	secretIndex, secretOK := indexes["secret access key"]
	if !accessOK || !secretOK {
		return Credentials{}, ErrInvalidCredentials
	}
	credentials := Credentials{
		AccessKeyID:     append([]byte(nil), bytes.TrimSpace(records[1][accessIndex])...),
		SecretAccessKey: append([]byte(nil), bytes.TrimSpace(records[1][secretIndex])...),
	}
	if tokenIndex, ok := indexes["session token"]; ok {
		credentials.SessionToken = append([]byte(nil), bytes.TrimSpace(records[1][tokenIndex])...)
	}
	return credentials, nil
}

func parseCSVBytes(payload []byte) ([][][]byte, error) {
	var records [][][]byte
	var record [][]byte
	var field []byte
	quoted := false
	quoteClosed := false
	for index := 0; index <= len(payload); index++ {
		atEOF := index == len(payload)
		var current byte
		if !atEOF {
			current = payload[index]
		}
		if quoted {
			if atEOF {
				wipeCSVRecords(records)
				wipeCSVRecord(record)
				secretbootstrap.Wipe(field)
				return nil, ErrInvalidCredentials
			}
			if current == '"' {
				if index+1 < len(payload) && payload[index+1] == '"' {
					field = append(field, '"')
					index++
					continue
				}
				quoted = false
				quoteClosed = true
				continue
			}
			field = append(field, current)
			continue
		}
		if quoteClosed && !atEOF && current != ',' && current != '\r' && current != '\n' {
			wipeCSVRecords(records)
			wipeCSVRecord(record)
			secretbootstrap.Wipe(field)
			return nil, ErrInvalidCredentials
		}
		switch {
		case !quoteClosed && len(field) == 0 && current == '"':
			quoted = true
		case atEOF || current == ',' || current == '\r' || current == '\n':
			record = append(record, field)
			field = nil
			quoteClosed = false
			if atEOF || current == '\r' || current == '\n' {
				if current == '\r' && index+1 < len(payload) && payload[index+1] == '\n' {
					index++
				}
				emptyTrailingRecord := len(record) == 1 && len(record[0]) == 0 && (atEOF || len(records) > 0)
				if !emptyTrailingRecord {
					records = append(records, record)
				} else {
					wipeCSVRecord(record)
				}
				record = nil
				if len(records) > 2 {
					wipeCSVRecords(records)
					return nil, ErrInvalidCredentials
				}
			}
		case current == '"':
			wipeCSVRecords(records)
			wipeCSVRecord(record)
			secretbootstrap.Wipe(field)
			return nil, ErrInvalidCredentials
		default:
			field = append(field, current)
		}
	}
	return records, nil
}

func wipeCSVRecords(records [][][]byte) {
	for _, record := range records {
		wipeCSVRecord(record)
	}
}

func wipeCSVRecord(record [][]byte) {
	for _, field := range record {
		secretbootstrap.Wipe(field)
	}
}
