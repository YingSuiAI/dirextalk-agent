// Package awsartifactoriginassets exposes the reviewed artifact-origin
// templates and pinned Knowledge artifact catalog without a runtime filesystem
// dependency.
package awsartifactoriginassets

import _ "embed"

//go:embed storage.yaml
var storageTemplate []byte

//go:embed edge.yaml
var edgeTemplate []byte

//go:embed knowledge-artifacts.v1.json
var knowledgeCatalog []byte

func StorageTemplate() []byte { return append([]byte(nil), storageTemplate...) }
func EdgeTemplate() []byte    { return append([]byte(nil), edgeTemplate...) }
func KnowledgeCatalog() []byte {
	return append([]byte(nil), knowledgeCatalog...)
}
