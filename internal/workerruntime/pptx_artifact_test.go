package workerruntime

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestPPTXArtifactValidation(t *testing.T) {
	t.Parallel()
	valid := validPPTXBytes(t, false)
	if validatePPTXArtifact(valid) != nil {
		t.Fatal("valid PPTX was rejected")
	}
	if validatePPTXArtifact([]byte("not a zip")) == nil {
		t.Fatal("non-ZIP PPTX was accepted")
	}
	if validatePPTXArtifact(validPPTXBytes(t, true)) == nil {
		t.Fatal("PPTX with an external relationship was accepted")
	}
}

func validPPTXBytes(t *testing.T, externalRelationship bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entries := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="officeDocument" Target="ppt/presentation.xml"/>` +
			`</Relationships>`,
		"ppt/presentation.xml": `<?xml version="1.0" encoding="UTF-8"?>` +
			`<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>`,
	}
	if externalRelationship {
		entries["ppt/_rels/presentation.xml.rels"] =
			`<Relationships><Relationship TargetMode="External" Target="https://example.com"/></Relationships>`
	}
	for name, content := range entries {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
