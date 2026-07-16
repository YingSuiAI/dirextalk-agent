package publicweb

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"golang.org/x/net/html"
)

var fetchedCredentialPattern = regexp.MustCompile(`(?i)\b(authorization|proxy[_-]?authorization|api[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token|signature|credential|client[_-]?secret|password|secret|token|key|x-amz-[a-z0-9_-]+)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;}\]]+)`)

func extractSafeText(mediaType string, body []byte) (string, error) {
	var value string
	switch mediaType {
	case "text/html":
		document, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			return "", ErrResponseRejected
		}
		var builder strings.Builder
		appendHTMLText(&builder, document)
		value = builder.String()
	case "application/json":
		var compact bytes.Buffer
		if err := json.Compact(&compact, body); err != nil {
			return "", ErrResponseRejected
		}
		value = compact.String()
	case "text/plain", "text/markdown":
		value = string(body)
	default:
		return "", ErrUnsupportedContentType
	}
	return normalizeText(value), nil
}

func appendHTMLText(builder *strings.Builder, node *html.Node) {
	if node.Type == html.ElementNode && ignoredElement(node.Data) {
		return
	}
	if node.Type == html.TextNode {
		builder.WriteString(node.Data)
		builder.WriteByte(' ')
	}
	block := node.Type == html.ElementNode && blockElement(node.Data)
	if block {
		builder.WriteByte('\n')
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		appendHTMLText(builder, child)
	}
	if block {
		builder.WriteByte('\n')
	}
}

func ignoredElement(name string) bool {
	switch strings.ToLower(name) {
	case "script", "style", "noscript", "template", "svg", "canvas", "iframe", "object", "embed":
		return true
	default:
		return false
	}
}

func blockElement(name string) bool {
	switch strings.ToLower(name) {
	case "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul":
		return true
	default:
		return false
	}
}

func normalizeText(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(character rune) rune {
		switch character {
		case '\n', '\r', '\t':
			return character
		}
		if character == utf8.RuneError || unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	normalized := make([]string, 0, len(lines))
	blank := false
	for _, line := range lines {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			if blank || len(normalized) == 0 {
				continue
			}
			blank = true
			normalized = append(normalized, "")
			continue
		}
		blank = false
		normalized = append(normalized, line)
	}
	return strings.TrimSpace(strings.Join(normalized, "\n"))
}

func redactFetchedText(value string) string {
	value = security.RedactText(value)
	value = fetchedCredentialPattern.ReplaceAllString(value, "$1=[redacted]")
	return normalizeText(value)
}
