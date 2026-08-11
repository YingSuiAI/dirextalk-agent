// Package artifactmedia defines the closed set of user-facing Worker artifact
// media types shared by runtime, storage, and delivery validation.
package artifactmedia

const (
	JSON = "application/json"
	Text = "text/plain; charset=utf-8"
	PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
)

func Supported(value string) bool {
	switch value {
	case JSON, Text, PPTX:
		return true
	default:
		return false
	}
}

func Textual(value string) bool {
	return value == JSON || value == Text
}

func Extension(value string) (string, bool) {
	switch value {
	case JSON:
		return "json", true
	case Text:
		return "txt", true
	case PPTX:
		return "pptx", true
	default:
		return "", false
	}
}
