// Package canonical implements the deterministic serialization used by signed
// cloud-control contracts. It intentionally accepts only JSON-compatible,
// integer-only values so implementations in other languages can reproduce the
// exact bytes without depending on Go-specific types.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Algorithm is persisted with every hash-bearing contract. Changing the
// encoding requires a new algorithm identifier and contract version.
const Algorithm = "deterministic-cbor-sha256"

// Marshal converts v through its JSON contract and encodes the resulting value
// using RFC 8949 core deterministic CBOR. Floating-point fields are rejected,
// including values that JSON would otherwise serialize as whole numbers.
func Marshal(v any) ([]byte, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON projection: %w", err)
	}
	if err := rejectFloats(reflect.ValueOf(v), make(map[visit]struct{})); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.UseNumber()
	var projected any
	if err := decoder.Decode(&projected); err != nil {
		return nil, fmt.Errorf("decode canonical JSON projection: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode canonical JSON projection: trailing value")
		}
		return nil, fmt.Errorf("decode canonical JSON projection: %w", err)
	}

	var out bytes.Buffer
	if err := encode(&out, projected); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Digest returns a lowercase, algorithm-qualified SHA-256 digest of Marshal(v).
func Digest(v any) (string, error) {
	encoded, err := Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type mapEntry struct {
	key   []byte
	value any
}

func encode(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteByte(0xf6)
	case bool:
		if value {
			out.WriteByte(0xf5)
		} else {
			out.WriteByte(0xf4)
		}
	case string:
		writeHead(out, 3, uint64(len(value)))
		out.WriteString(value)
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return fmt.Errorf("canonical contracts cannot contain floating-point number %q", value)
		}
		number, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			unsigned, unsignedErr := strconv.ParseUint(string(value), 10, 64)
			if unsignedErr != nil {
				return fmt.Errorf("canonical contract number %q is not an integer: %w", value, err)
			}
			writeHead(out, 0, unsigned)
			return nil
		}
		if number >= 0 {
			writeHead(out, 0, uint64(number))
		} else {
			writeHead(out, 1, uint64(-(number + 1)))
		}
	case []any:
		writeHead(out, 4, uint64(len(value)))
		for _, item := range value {
			if err := encode(out, item); err != nil {
				return err
			}
		}
	case map[string]any:
		entries := make([]mapEntry, 0, len(value))
		for key, item := range value {
			var encodedKey bytes.Buffer
			if err := encode(&encodedKey, key); err != nil {
				return err
			}
			entries = append(entries, mapEntry{key: encodedKey.Bytes(), value: item})
		}
		sort.Slice(entries, func(i, j int) bool {
			return bytes.Compare(entries[i].key, entries[j].key) < 0
		})
		writeHead(out, 5, uint64(len(entries)))
		for _, entry := range entries {
			out.Write(entry.key)
			if err := encode(out, entry.value); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported canonical value type %T", value)
	}
	return nil
}

func writeHead(out *bytes.Buffer, major byte, value uint64) {
	switch {
	case value <= 23:
		out.WriteByte(major<<5 | byte(value))
	case value <= 0xff:
		out.WriteByte(major<<5 | 24)
		out.WriteByte(byte(value))
	case value <= 0xffff:
		out.WriteByte(major<<5 | 25)
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], uint16(value))
		out.Write(encoded[:])
	case value <= 0xffffffff:
		out.WriteByte(major<<5 | 26)
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(value))
		out.Write(encoded[:])
	default:
		out.WriteByte(major<<5 | 27)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		out.Write(encoded[:])
	}
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

func rejectFloats(value reflect.Value, seen map[visit]struct{}) error {
	if !value.IsValid() {
		return nil
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return nil
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		if value.Kind() == reflect.Pointer {
			key := visit{typ: value.Type(), ptr: value.Pointer()}
			if _, exists := seen[key]; exists {
				return nil
			}
			seen[key] = struct{}{}
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("canonical contracts cannot contain floating-point field of type %s", value.Type())
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() || field.Tag.Get("json") == "-" {
				continue
			}
			if err := rejectFloats(value.Field(i), seen); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if err := rejectFloats(value.Index(i), seen); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("canonical contracts require string map keys, got %s", value.Type().Key())
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if err := rejectFloats(iterator.Key(), seen); err != nil {
				return err
			}
			if err := rejectFloats(iterator.Value(), seen); err != nil {
				return err
			}
		}
	}
	return nil
}
