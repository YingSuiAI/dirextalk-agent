package installer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	maxCBORDepth = 24
	maxCBORItems = 8192
)

// DecodeCanonical decodes the integer-only deterministic CBOR subset emitted
// by internal/cloud/canonical. It rejects duplicate keys, tags, byte strings,
// floats, indefinite lengths, non-shortest integers, unknown JSON fields, and
// any encoding that does not round-trip byte-for-byte.
func DecodeCanonical(raw []byte, target any) error {
	if len(raw) == 0 || target == nil {
		return errorf(CodeInvalidRequest, "empty CBOR payload or target")
	}
	decoder := cborDecoder{raw: raw}
	value, err := decoder.decode(0)
	if err != nil {
		return err
	}
	if decoder.offset != len(raw) {
		return errorf(CodeNonCanonicalCBOR, "trailing CBOR data")
	}
	projected, err := json.Marshal(value)
	if err != nil {
		return errorf(CodeInvalidRequest, "project decoded CBOR: %v", err)
	}
	jsonDecoder := json.NewDecoder(bytes.NewReader(projected))
	jsonDecoder.DisallowUnknownFields()
	if err := jsonDecoder.Decode(target); err != nil {
		return errorf(CodeInvalidRequest, "decode CBOR contract: %v", err)
	}
	var extra any
	if err := jsonDecoder.Decode(&extra); err != io.EOF {
		return errorf(CodeInvalidRequest, "decode CBOR contract trailing JSON")
	}
	canonicalRaw, err := canonical.Marshal(target)
	if err != nil {
		return errorf(CodeInvalidRequest, "canonicalize decoded contract: %v", err)
	}
	if !bytes.Equal(raw, canonicalRaw) {
		return errorf(CodeNonCanonicalCBOR, "CBOR bytes are not the canonical contract encoding")
	}
	return nil
}

type cborDecoder struct {
	raw    []byte
	offset int
	items  int
}

func (d *cborDecoder) decode(depth int) (any, error) {
	if depth > maxCBORDepth {
		return nil, errorf(CodeInvalidRequest, "CBOR nesting exceeds limit")
	}
	d.items++
	if d.items > maxCBORItems || d.offset >= len(d.raw) {
		return nil, errorf(CodeInvalidRequest, "CBOR item limit or unexpected end")
	}
	head := d.raw[d.offset]
	d.offset++
	major, additional := head>>5, head&0x1f
	if additional == 31 {
		return nil, errorf(CodeNonCanonicalCBOR, "indefinite CBOR values are forbidden")
	}
	value, err := d.readAdditional(additional)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return value, nil
	case 1:
		if value > math.MaxInt64 {
			return nil, errorf(CodeInvalidRequest, "negative CBOR integer overflows int64")
		}
		return -1 - int64(value), nil
	case 3:
		if value > uint64(len(d.raw)-d.offset) {
			return nil, errorf(CodeInvalidRequest, "truncated CBOR text")
		}
		text := d.raw[d.offset : d.offset+int(value)]
		d.offset += int(value)
		if !utf8.Valid(text) {
			return nil, errorf(CodeInvalidRequest, "CBOR text is not UTF-8")
		}
		return string(text), nil
	case 4:
		if value > maxCBORItems || value > uint64(len(d.raw)) {
			return nil, errorf(CodeInvalidRequest, "CBOR array exceeds limit")
		}
		items := make([]any, 0, int(value))
		for range value {
			item, decodeErr := d.decode(depth + 1)
			if decodeErr != nil {
				return nil, decodeErr
			}
			items = append(items, item)
		}
		return items, nil
	case 5:
		if value > maxCBORItems || value > uint64(len(d.raw)) {
			return nil, errorf(CodeInvalidRequest, "CBOR map exceeds limit")
		}
		items := make(map[string]any, int(value))
		for range value {
			keyValue, decodeErr := d.decode(depth + 1)
			if decodeErr != nil {
				return nil, decodeErr
			}
			key, ok := keyValue.(string)
			if !ok {
				return nil, errorf(CodeInvalidRequest, "CBOR map key is not text")
			}
			if _, exists := items[key]; exists {
				return nil, errorf(CodeNonCanonicalCBOR, "duplicate CBOR map key")
			}
			item, decodeErr := d.decode(depth + 1)
			if decodeErr != nil {
				return nil, decodeErr
			}
			items[key] = item
		}
		return items, nil
	case 7:
		switch additional {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, errorf(CodeNonCanonicalCBOR, "unsupported CBOR simple or floating value")
		}
	default:
		return nil, errorf(CodeNonCanonicalCBOR, "unsupported CBOR major type %d", major)
	}
}

func (d *cborDecoder) readAdditional(additional byte) (uint64, error) {
	switch {
	case additional <= 23:
		return uint64(additional), nil
	case additional == 24:
		value, err := d.readUint(1)
		if err == nil && value < 24 {
			return 0, errorf(CodeNonCanonicalCBOR, "non-shortest CBOR uint8")
		}
		return value, err
	case additional == 25:
		value, err := d.readUint(2)
		if err == nil && value <= math.MaxUint8 {
			return 0, errorf(CodeNonCanonicalCBOR, "non-shortest CBOR uint16")
		}
		return value, err
	case additional == 26:
		value, err := d.readUint(4)
		if err == nil && value <= math.MaxUint16 {
			return 0, errorf(CodeNonCanonicalCBOR, "non-shortest CBOR uint32")
		}
		return value, err
	case additional == 27:
		value, err := d.readUint(8)
		if err == nil && value <= math.MaxUint32 {
			return 0, errorf(CodeNonCanonicalCBOR, "non-shortest CBOR uint64")
		}
		return value, err
	default:
		return 0, errorf(CodeNonCanonicalCBOR, "reserved CBOR additional information")
	}
}

func (d *cborDecoder) readUint(size int) (uint64, error) {
	if size < 1 || d.offset+size > len(d.raw) {
		return 0, errorf(CodeInvalidRequest, "truncated CBOR integer")
	}
	var value uint64
	switch size {
	case 1:
		value = uint64(d.raw[d.offset])
	case 2:
		value = uint64(binary.BigEndian.Uint16(d.raw[d.offset : d.offset+size]))
	case 4:
		value = uint64(binary.BigEndian.Uint32(d.raw[d.offset : d.offset+size]))
	case 8:
		value = binary.BigEndian.Uint64(d.raw[d.offset : d.offset+size])
	default:
		return 0, fmt.Errorf("unsupported integer width %d", size)
	}
	d.offset += size
	return value, nil
}
