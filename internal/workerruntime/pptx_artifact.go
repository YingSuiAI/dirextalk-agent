package workerruntime

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	maximumOfficeArchiveEntries           = 2048
	maximumOfficeArchiveUncompressedBytes = 64 << 20
	maximumOfficeArchiveEntryBytes        = 16 << 20
)

var errInvalidPPTXArtifact = errors.New("invalid PPTX artifact")

func validatePPTXArtifact(content []byte) error {
	return validateOfficeArchive(content, "ppt/presentation.xml", true)
}

func validateOfficeArchive(content []byte, requiredDocument string, allowWorkbook bool) error {
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil || len(archive.File) == 0 || len(archive.File) > maximumOfficeArchiveEntries {
		return errInvalidPPTXArtifact
	}
	seen := make(map[string]struct{}, len(archive.File))
	required := map[string]bool{
		"[Content_Types].xml": false,
		"_rels/.rels":         false,
		requiredDocument:      false,
	}
	var uncompressed uint64
	for _, file := range archive.File {
		name := file.Name
		if !validOfficeArchivePath(name) || file.Flags&0x1 != 0 ||
			file.FileInfo().Mode()&os.ModeSymlink != 0 {
			return errInvalidPPTXArtifact
		}
		if _, duplicate := seen[name]; duplicate {
			return errInvalidPPTXArtifact
		}
		seen[name] = struct{}{}
		if _, ok := required[name]; ok {
			required[name] = true
		}
		if strings.HasSuffix(name, "/") {
			continue
		}
		if file.UncompressedSize64 > maximumOfficeArchiveEntryBytes {
			return errInvalidPPTXArtifact
		}
		uncompressed += file.UncompressedSize64
		if uncompressed > maximumOfficeArchiveUncompressedBytes ||
			!allowedOfficeEntry(name, allowWorkbook) {
			return errInvalidPPTXArtifact
		}
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".xml"), strings.HasSuffix(lower, ".rels"):
			raw, readErr := readOfficeEntry(file)
			if readErr != nil || inspectOfficeXML(raw) != nil ||
				(name == "[Content_Types].xml" &&
					!hasRequiredOfficeContentType(raw, requiredDocument)) {
				clear(raw)
				return errInvalidPPTXArtifact
			}
			clear(raw)
		case strings.HasSuffix(lower, ".xlsx"):
			raw, readErr := readOfficeEntry(file)
			if readErr != nil || validateOfficeArchive(raw, "xl/workbook.xml", false) != nil {
				clear(raw)
				return errInvalidPPTXArtifact
			}
			clear(raw)
		}
	}
	for _, present := range required {
		if !present {
			return errInvalidPPTXArtifact
		}
	}
	return nil
}

func hasRequiredOfficeContentType(raw []byte, requiredDocument string) bool {
	want := ""
	switch requiredDocument {
	case "ppt/presentation.xml":
		want = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
	case "xl/workbook.xml":
		want = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
	default:
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return false
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Override" {
			continue
		}
		partName, contentType := "", ""
		for _, attribute := range start.Attr {
			switch attribute.Name.Local {
			case "PartName":
				partName = strings.TrimPrefix(attribute.Value, "/")
			case "ContentType":
				contentType = attribute.Value
			}
		}
		if partName == requiredDocument && contentType == want {
			return true
		}
	}
}

func validOfficeArchivePath(name string) bool {
	return name != "" && len(name) <= maxPiArtifactPathBytes &&
		utf8.ValidString(name) && strings.TrimSpace(name) == name &&
		!strings.HasPrefix(name, "/") && !strings.Contains(name, "\\") &&
		strings.IndexFunc(name, unicode.IsControl) < 0 &&
		path.Clean(name) == strings.TrimSuffix(name, "/") &&
		name != "." && !strings.HasPrefix(name, "../")
}

func allowedOfficeEntry(name string, allowWorkbook bool) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{
		"ppt/activex/", "ppt/ctrlprops/", "ppt/vbaproject",
		"ppt/embeddings/oleobject", "xl/activex/", "xl/ctrlprops/",
		"xl/vbaproject", "xl/embeddings/oleobject",
	} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	extension := path.Ext(lower)
	switch extension {
	case ".xml", ".rels", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
		".tif", ".tiff", ".svg", ".emf", ".wmf", ".mp3", ".wav",
		".mp4", ".m4a":
		return true
	case ".xlsx":
		return allowWorkbook && strings.HasPrefix(lower, "ppt/embeddings/")
	default:
		return false
	}
}

func readOfficeEntry(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, errInvalidPPTXArtifact
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, maximumOfficeArchiveEntryBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumOfficeArchiveEntryBytes {
		clear(raw)
		return nil, errInvalidPPTXArtifact
	}
	return raw, nil
}

func inspectOfficeXML(raw []byte) error {
	if !utf8.Valid(raw) || security.ContainsLikelySecret(string(raw)) {
		return errInvalidPPTXArtifact
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errInvalidPPTXArtifact
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, attribute := range start.Attr {
			if strings.EqualFold(attribute.Name.Local, "TargetMode") &&
				strings.EqualFold(strings.TrimSpace(attribute.Value), "External") {
				return errInvalidPPTXArtifact
			}
			if strings.Contains(strings.ToLower(attribute.Value), "macroenabled") {
				return errInvalidPPTXArtifact
			}
		}
	}
}
