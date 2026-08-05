package coreteam

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testOwnerID      = "@agent-team:example.test"
	testConversation = "11111111-1111-4111-8111-111111111111"
	testCredential   = "22222222-2222-4222-8222-222222222222"
	testRuntimeID    = "official-pi-0.83.0"
	testImageDigest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAMI          = "ami-0123456789abcdef0"
	testPlanID       = "33333333-3333-4333-8333-333333333333"
	testTaskID       = "44444444-4444-4444-8444-444444444444"
	testConfirmation = "55555555-5555-4555-8555-555555555555"
)

var testNow = time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)

type fakeRuntimeCatalog struct {
	binding RuntimeBinding
	err     error
	wantID  string
}

func (f fakeRuntimeCatalog) ResolveRuntime(_ context.Context, runtimeID string) (RuntimeBinding, error) {
	if f.wantID != "" && runtimeID != f.wantID {
		return RuntimeBinding{}, errors.New("provider leaked runtime detail")
	}
	return f.binding, f.err
}

type fakeQuoteProvider struct {
	quote QuoteBinding
	err   error
	seen  *QuoteRequest
}

func (f fakeQuoteProvider) Quote(_ context.Context, request QuoteRequest) (QuoteBinding, error) {
	if f.seen != nil {
		*f.seen = request
	}
	return f.quote, f.err
}

func validRuntime() RuntimeBinding {
	return RuntimeBinding{
		RuntimeID:    testRuntimeID,
		Adapter:      AdapterPiV1,
		ImageDigest:  testImageDigest,
		AMIID:        testAMI,
		OutputTokens: 32_768,
	}
}

func validQuote() QuoteBinding {
	return QuoteBinding{
		Region:           OsakaRegion,
		AvailabilityZone: "ap-northeast-3a",
		InstanceType:     MVPInstanceType,
		Currency:         "USD",
		Amount:           "0.0256",
		HardBudget:       "1.00",
		ExpiresAt:        testNow.Add(15 * time.Minute),
	}
}

func validCommand() CompileCommand {
	return CompileCommand{
		OwnerID:            testOwnerID,
		AccountGeneration:  7,
		Goal:               "research and verify",
		ConversationID:     testConversation,
		CredentialID:       testCredential,
		CredentialRevision: 3,
		RuntimeID:          testRuntimeID,
		Roles: []RoleProposal{
			{RoleID: "research", Goal: "collect primary evidence", Capabilities: []Capability{CapabilityWebResearch}},
			{RoleID: "review", Goal: "review the evidence", DependsOn: []string{"research"}, Capabilities: []Capability{CapabilityWebResearch}},
		},
	}
}

func testCompiler(catalog RuntimeCatalog, quotes QuoteProvider) *Compiler {
	ids := []string{testPlanID, testTaskID, testConfirmation}
	next := 0
	return NewCompiler(catalog, quotes,
		WithClock(func() time.Time { return testNow }),
		WithIDGenerator(func() (string, error) {
			if next >= len(ids) {
				return "", errors.New("too many IDs requested")
			}
			id := ids[next]
			next++
			return id, nil
		}),
	)
}

func TestCompilerProducesBoundedPiPlan(t *testing.T) {
	var quoted QuoteRequest
	c := testCompiler(
		fakeRuntimeCatalog{binding: validRuntime(), wantID: testRuntimeID},
		fakeQuoteProvider{quote: validQuote(), seen: &quoted},
	)

	plan, err := c.Compile(context.Background(), validCommand())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Roles) != 2 || plan.Runtime.Adapter != AdapterPiV1 || !plan.Valid() {
		t.Fatalf("plan=%#v", plan)
	}
	if plan.OwnerID != testOwnerID || plan.AccountGeneration != 7 || plan.Revision != 1 || plan.Status != PlanWaitingUser {
		t.Fatalf("owner/generation/revision/status not bound: %#v", plan)
	}
	if plan.PlanID != testPlanID || plan.TaskID != testTaskID || plan.ConfirmationID != testConfirmation {
		t.Fatalf("server IDs not bound: %#v", plan)
	}
	if quoted.Region != OsakaRegion || quoted.InstanceType != MVPInstanceType || quoted.RoleCount != 2 || quoted.RuntimeID != testRuntimeID {
		t.Fatalf("quote request escaped the MVP profile: %#v", quoted)
	}
}

func TestCompilerAcceptsOneToThreeAcyclicRoles(t *testing.T) {
	for count := 1; count <= MaxRoles; count++ {
		count := count
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			cmd := validCommand()
			cmd.Roles = make([]RoleProposal, 0, count)
			for i := 0; i < count; i++ {
				role := RoleProposal{RoleID: string(rune('a' + i)), Goal: "bounded work", Capabilities: []Capability{CapabilityWebResearch}}
				if i > 0 {
					role.DependsOn = []string{string(rune('a' + i - 1))}
				}
				cmd.Roles = append(cmd.Roles, role)
			}
			if _, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), cmd); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCompilerRejectsInvalidCommands(t *testing.T) {
	tests := map[string]func(*CompileCommand){
		"owner blank":              func(c *CompileCommand) { c.OwnerID = " " },
		"owner too long":           func(c *CompileCommand) { c.OwnerID = strings.Repeat("a", MaxOwnerIDBytes+1) },
		"owner control character":  func(c *CompileCommand) { c.OwnerID = "@agent\nteam:example.test" },
		"generation absent":        func(c *CompileCommand) { c.AccountGeneration = 0 },
		"conversation not UUID":    func(c *CompileCommand) { c.ConversationID = "conversation" },
		"credential not UUID":      func(c *CompileCommand) { c.CredentialID = "credential" },
		"credential revision zero": func(c *CompileCommand) { c.CredentialRevision = 0 },
		"goal blank":               func(c *CompileCommand) { c.Goal = " " },
		"no roles":                 func(c *CompileCommand) { c.Roles = nil },
		"fourth role": func(c *CompileCommand) {
			c.Roles = append(c.Roles,
				RoleProposal{RoleID: "write", Goal: "write", Capabilities: []Capability{CapabilityRepositoryWrite}},
				RoleProposal{RoleID: "test", Goal: "test", Capabilities: []Capability{CapabilityTest}},
			)
		},
		"duplicate role":     func(c *CompileCommand) { c.Roles[1].RoleID = c.Roles[0].RoleID },
		"unknown dependency": func(c *CompileCommand) { c.Roles[1].DependsOn = []string{"missing"} },
		"self dependency":    func(c *CompileCommand) { c.Roles[0].DependsOn = []string{"research"} },
		"cycle": func(c *CompileCommand) {
			c.Roles[0].DependsOn = []string{"review"}
			c.Roles[1].DependsOn = []string{"research"}
		},
		"duplicate dependency": func(c *CompileCommand) { c.Roles[1].DependsOn = []string{"research", "research"} },
		"unknown capability":   func(c *CompileCommand) { c.Roles[0].Capabilities = []Capability{"aws.admin"} },
		"duplicate capability": func(c *CompileCommand) {
			c.Roles[0].Capabilities = []Capability{CapabilityWebResearch, CapabilityWebResearch}
		},
		"unknown runtime": func(c *CompileCommand) { c.RuntimeID = "user-image" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := validCommand()
			mutate(&cmd)
			_, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), cmd)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCompilerRejectsInvalidRuntimeAndQuoteBindings(t *testing.T) {
	runtimes := map[string]func(*RuntimeBinding){
		"wrong runtime":     func(v *RuntimeBinding) { v.RuntimeID = "other" },
		"wrong adapter":     func(v *RuntimeBinding) { v.Adapter = "shell" },
		"mutable image":     func(v *RuntimeBinding) { v.ImageDigest = "latest" },
		"invalid AMI":       func(v *RuntimeBinding) { v.AMIID = "ami-latest" },
		"noncanonical AMI":  func(v *RuntimeBinding) { v.AMIID = "ami-012345678" },
		"zero token budget": func(v *RuntimeBinding) { v.OutputTokens = 0 },
		"huge token budget": func(v *RuntimeBinding) { v.OutputTokens = MaxOutputTokens + 1 },
	}
	for name, mutate := range runtimes {
		t.Run(name, func(t *testing.T) {
			runtime := validRuntime()
			mutate(&runtime)
			_, err := testCompiler(fakeRuntimeCatalog{binding: runtime}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), validCommand())
			if !errors.Is(err, ErrRuntimeUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	quotes := map[string]func(*QuoteBinding){
		"wrong region":     func(v *QuoteBinding) { v.Region = "us-east-1" },
		"wrong zone":       func(v *QuoteBinding) { v.AvailabilityZone = "ap-northeast-1a" },
		"wrong instance":   func(v *QuoteBinding) { v.InstanceType = "t3.micro" },
		"invalid currency": func(v *QuoteBinding) { v.Currency = "usd" },
		"invalid amount":   func(v *QuoteBinding) { v.Amount = "NaN" },
		"negative amount":  func(v *QuoteBinding) { v.Amount = "-1" },
		"zero budget":      func(v *QuoteBinding) { v.HardBudget = "0" },
		"over budget":      func(v *QuoteBinding) { v.Amount = "2.00"; v.HardBudget = "1.00" },
		"expired":          func(v *QuoteBinding) { v.ExpiresAt = testNow },
	}
	for name, mutate := range quotes {
		t.Run(name, func(t *testing.T) {
			quote := validQuote()
			mutate(&quote)
			_, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: quote}).Compile(context.Background(), validCommand())
			if !errors.Is(err, ErrQuoteUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCompilerReturnsClosedErrorsAndHonorsCancellation(t *testing.T) {
	raw := errors.New("AKIA raw provider failure")
	_, err := testCompiler(fakeRuntimeCatalog{err: raw}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), validCommand())
	if !errors.Is(err, ErrRuntimeUnavailable) || strings.Contains(err.Error(), raw.Error()) {
		t.Fatalf("runtime err leaked: %v", err)
	}
	_, err = testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{err: raw}).Compile(context.Background(), validCommand())
	if !errors.Is(err, ErrQuoteUnavailable) || strings.Contains(err.Error(), raw.Error()) {
		t.Fatalf("quote err leaked: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(ctx, validCommand())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestCompilerRejectsInvalidOrRepeatedServerIDsWithoutLeakingGeneratorErrors(t *testing.T) {
	tests := map[string]IDGenerator{
		"generator error": func() (string, error) { return "", errors.New("internal ID provider detail") },
		"invalid UUID":    func() (string, error) { return "generated-id", nil },
		"repeated UUID":   func() (string, error) { return testPlanID, nil },
	}
	for name, generator := range tests {
		t.Run(name, func(t *testing.T) {
			compiler := NewCompiler(
				fakeRuntimeCatalog{binding: validRuntime()},
				fakeQuoteProvider{quote: validQuote()},
				WithClock(func() time.Time { return testNow }),
				WithIDGenerator(generator),
			)
			_, err := compiler.Compile(context.Background(), validCommand())
			if !errors.Is(err, ErrIdentityUnavailable) || strings.Contains(err.Error(), "provider") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCompilerDoesNotPublishAPlanCanceledDuringIDGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ids := []string{testPlanID, testTaskID, testConfirmation}
	next := 0
	compiler := NewCompiler(
		fakeRuntimeCatalog{binding: validRuntime()},
		fakeQuoteProvider{quote: validQuote()},
		WithClock(func() time.Time { return testNow }),
		WithIDGenerator(func() (string, error) {
			id := ids[next]
			next++
			if next == len(ids) {
				cancel()
			}
			return id, nil
		}),
	)
	if _, err := compiler.Compile(ctx, validCommand()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestCompilerUsesTheOfficialRuntimeWhenTheRequestOmitsOne(t *testing.T) {
	command := validCommand()
	command.RuntimeID = ""
	plan, err := testCompiler(
		fakeRuntimeCatalog{binding: validRuntime(), wantID: OfficialRuntimeID},
		fakeQuoteProvider{quote: validQuote()},
	).Compile(context.Background(), command)
	if err != nil || plan.Runtime.RuntimeID != OfficialRuntimeID {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
}

func TestCompilerRechecksQuoteFreshnessAfterExternalWork(t *testing.T) {
	current := testNow
	ids := []string{testPlanID, testTaskID, testConfirmation}
	idNext := 0
	compiler := NewCompiler(
		fakeRuntimeCatalog{binding: validRuntime()},
		fakeQuoteProvider{quote: validQuote()},
		WithClock(func() time.Time { return current }),
		WithIDGenerator(func() (string, error) {
			if idNext >= len(ids) {
				return "", errors.New("too many IDs requested")
			}
			value := ids[idNext]
			idNext++
			if idNext == len(ids) {
				current = testNow.Add(16 * time.Minute)
			}
			return value, nil
		}),
	)
	_, err := compiler.Compile(context.Background(), validCommand())
	if !errors.Is(err, ErrQuoteUnavailable) {
		t.Fatalf("expired quote published: %v", err)
	}
}

func TestPlanDigestIsCanonicalAndSemantic(t *testing.T) {
	cmd := validCommand()
	cmd.Roles[0].Capabilities = []Capability{CapabilityRepositoryRead, CapabilityWebResearch}
	cmd.Roles[1].DependsOn = []string{"research"}
	first, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}

	reordered := validCommand()
	reordered.Roles = []RoleProposal{
		{RoleID: "review", Goal: "review the evidence", DependsOn: []string{"research"}, Capabilities: []Capability{CapabilityWebResearch}},
		{RoleID: "research", Goal: "collect primary evidence", Capabilities: []Capability{CapabilityWebResearch, CapabilityRepositoryRead}},
	}
	second, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), reordered)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digest changed after semantic reorder: %s != %s", first.Digest, second.Digest)
	}

	second.PlanID = "66666666-6666-4666-8666-666666666666"
	second.TaskID = "77777777-7777-4777-8777-777777777777"
	second.ConfirmationID = "88888888-8888-4888-8888-888888888888"
	second.Status = PlanApproved
	if got, err := second.SemanticDigest(); err != nil || got != first.Digest {
		t.Fatalf("mutable identity/status entered digest: got=%s err=%v", got, err)
	}
	second.AccountGeneration++
	if got, err := second.SemanticDigest(); err != nil || got == first.Digest {
		t.Fatalf("generation missing from digest: got=%s err=%v", got, err)
	}
}

func TestPlanValidationRejectsMutationAndNonCanonicalCollections(t *testing.T) {
	plan, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), validCommand())
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*Plan){
		"digest mismatch":         func(v *Plan) { v.Goal = "changed" },
		"noncanonical role order": func(v *Plan) { v.Roles[0], v.Roles[1] = v.Roles[1], v.Roles[0] },
		"bad status":              func(v *Plan) { v.Status = "draft" },
		"bad plan id":             func(v *Plan) { v.PlanID = "plan" },
		"bad generation":          func(v *Plan) { v.AccountGeneration = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := plan.Clone()
			mutate(&candidate)
			if candidate.Valid() {
				t.Fatalf("candidate unexpectedly valid: %#v", candidate)
			}
		})
	}
}

func TestPlanSeparatesStructuralValidityFromQuoteFreshness(t *testing.T) {
	plan, err := testCompiler(fakeRuntimeCatalog{binding: validRuntime()}, fakeQuoteProvider{quote: validQuote()}).Compile(context.Background(), validCommand())
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ValidateAt(testNow); err != nil {
		t.Fatalf("fresh plan rejected: %v", err)
	}
	if err := plan.ValidateAt(plan.Quote.ExpiresAt); !errors.Is(err, ErrQuoteUnavailable) {
		t.Fatalf("expired quote accepted: %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("historical structural record became corrupt: %v", err)
	}
}

func TestScopeValidationBindsOwnerAndAccountGeneration(t *testing.T) {
	if err := (Scope{OwnerID: testOwnerID, AccountGeneration: 7}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []Scope{
		{},
		{OwnerID: " "},
		{OwnerID: "@agent\x00team:example.test", AccountGeneration: 1},
		{OwnerID: "@agent\rteam:example.test", AccountGeneration: 1},
		{OwnerID: "@agent\tteam:example.test", AccountGeneration: 1},
		{OwnerID: strings.Repeat("x", MaxOwnerIDBytes+1), AccountGeneration: 1},
		{OwnerID: testOwnerID, AccountGeneration: 0},
		{OwnerID: testOwnerID, AccountGeneration: -1},
	} {
		if !errors.Is(scope.Validate(), ErrInvalid) {
			t.Fatalf("scope unexpectedly valid: %#v", scope)
		}
	}
}

func TestPublicDomainContainsNoFreeFormOrCredentialMaterial(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(CompileCommand{}),
		reflect.TypeOf(Plan{}),
		reflect.TypeOf(RuntimeBinding{}),
		reflect.TypeOf(QuoteBinding{}),
		reflect.TypeOf(Role{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.ToLower(field.Name)
			if field.Type.Kind() == reflect.Map || field.Type == reflect.TypeOf([]byte(nil)) || strings.Contains(name, "secret") || strings.Contains(name, "accesskey") || strings.Contains(name, "command") || strings.Contains(name, "url") || strings.Contains(name, "providererror") {
				t.Fatalf("%s exposes forbidden field %s %s", typ.Name(), field.Name, field.Type)
			}
		}
	}
}
