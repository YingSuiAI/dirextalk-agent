package coreconversation

import (
	"strings"
	"unicode"
)

// answerReferences preserves linked artifacts before applying the public bound.
// URI text only selects an already validated transcript reference; neither a
// model-created reference nor a URL can create artifact authority.
func answerReferences(content string, proposed []Reference, transcript []Message) []Reference {
	links := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(content, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("()<>[]\"'`", r)
	}) {
		if strings.HasPrefix(token, "dirextalk-artifact://") {
			links[token] = struct{}{}
		}
	}
	known := make(map[string]struct{})
	var linked []Reference
	collect := func(references []Reference) {
		for _, reference := range references {
			if reference.Kind != "execution_artifact" || reference.Validate() != nil {
				continue
			}
			known[referenceKey(reference)] = struct{}{}
			uri := "dirextalk-artifact://" + reference.RecordKind + "/" + reference.ArtifactID
			if _, present := links[uri]; present {
				linked = append(linked, reference)
			}
		}
	}
	for _, message := range transcript {
		if message.Role != RoleAssistant && message.Role != RoleTool {
			continue
		}
		collect(message.References)
		for _, result := range message.ToolResults {
			collect(result.References)
		}
	}
	for _, reference := range proposed {
		if reference.Kind == "execution_artifact" {
			if _, present := known[referenceKey(reference)]; !present {
				continue
			}
		}
		linked = append(linked, reference)
	}
	return publicAnswerReferences(linked)
}
