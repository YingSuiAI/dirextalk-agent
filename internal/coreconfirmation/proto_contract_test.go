package coreconfirmation

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestConfirmationProtoDescriptorContract(t *testing.T) {
	file := agentv1.File_dirextalk_agent_v1_core_confirmation_proto
	if file == nil {
		t.Fatal("confirmation descriptor is missing")
	}
	if got := string(file.Package()); got != "dirextalk.agent.v1" {
		t.Fatalf("package=%q", got)
	}
	enum := file.Enums().ByName("CoreConfirmationState")
	if enum == nil || enum.Values().Len() != 6 {
		t.Fatalf("state enum shape is not stable")
	}
	for _, name := range []string{"CORE_CONFIRMATION_STATE_PENDING", "CORE_CONFIRMATION_STATE_CONFIRMED", "CORE_CONFIRMATION_STATE_CONSUMED", "CORE_CONFIRMATION_STATE_REJECTED", "CORE_CONFIRMATION_STATE_EXPIRED"} {
		if enum.Values().ByName(protoreflect.Name(name)) == nil {
			t.Fatalf("missing state %s", name)
		}
	}
	binding := file.Messages().ByName("CoreConfirmationBinding")
	for _, name := range []string{"operation_domain", "target_id", "target_revision", "content_digest", "parameter_digest", "network_digest", "secret_grant_digest", "network_grants", "secret_grants"} {
		if binding.Fields().ByName(protoreflect.Name(name)) == nil {
			t.Fatalf("missing binding field %s", name)
		}
	}
	grant := file.Messages().ByName("CoreSecretGrantDescriptor")
	if grant == nil {
		t.Fatal("missing secret grant descriptor")
	}
	for _, name := range []string{"reference_id", "binding_digest"} {
		field := grant.Fields().ByName(protoreflect.Name(name))
		if field == nil || field.Kind() != protoreflect.StringKind {
			t.Fatalf("invalid secret grant field %s", name)
		}
	}
	if field := grant.Fields().ByName("purpose"); field == nil || field.Kind() != protoreflect.EnumKind {
		t.Fatal("secret grant purpose must be closed enum")
	}
	for i := 0; i < grant.Fields().Len(); i++ {
		if grant.Fields().Get(i).Name() == "value" || grant.Fields().Get(i).Name() == "bytes" || grant.Fields().Get(i).Name() == "name" {
			t.Fatal("secret value field leaked")
		}
	}
	for _, name := range []string{"Get", "List", "Confirm", "Reject"} {
		if file.Services().ByName("ConfirmationService").Methods().ByName(protoreflect.Name(name)) == nil {
			t.Fatalf("missing rpc %s", name)
		}
	}
	service := file.Services().ByName("ConfirmationService")
	if service.Methods().Len() != 4 {
		t.Fatalf("confirmation service unexpectedly has %d methods", service.Methods().Len())
	}
	confirm := file.Messages().ByName("ConfirmationServiceConfirmRequest")
	if confirm.Fields().ByName("request_digest") != nil {
		t.Fatal("caller supplied request digest must not be public")
	}
	if confirm.Fields().ByName("binding") != nil {
		t.Fatal("caller echoed binding must not be public")
	}
}
