// Package awsfoundationassets exposes the immutable Foundation template to
// the Agent binary without a runtime filesystem or Node dependency.
package awsfoundationassets

import _ "embed"

//go:embed foundation.yaml
var foundationTemplate []byte

func Template() []byte { return append([]byte(nil), foundationTemplate...) }
