package pairing

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

func TestSessionValidationRejectsPlaintextShapedPersistence(t *testing.T) {
	session := validSession()
	if err := session.Validate(); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}
	session.RecipientKeyDigest = "password=pairing-canary"
	if err := session.Validate(); err != ErrInvalid {
		t.Fatalf("plaintext-shaped recipient digest error = %v, want ErrInvalid", err)
	}
}

func TestStateTransitionsAreFenced(t *testing.T) {
	if !CanRecordEnvelope(StatusWaitingPayload) || CanRecordEnvelope(StatusResuming) {
		t.Fatal("envelope transition fence is incorrect")
	}
	if status, err := RecordEnvelopeStatus(StatusWaitingPayload); err != nil || status != StatusWaitingUser {
		t.Fatalf("record envelope target = %q, %v; want waiting_user", status, err)
	}
	for _, status := range []Status{StatusPayloadReady, StatusWaitingUser} {
		if !CanBeginResume(status) {
			t.Fatalf("%s must be resumable", status)
		}
	}
	for _, status := range []Status{StatusSucceeded, StatusTimedOut, StatusFailed} {
		if !CanCompleteResume(status) {
			t.Fatalf("%s must be a valid terminal result", status)
		}
	}
	if CanCompleteResume(StatusWaitingUser) {
		t.Fatal("non-terminal completion was accepted")
	}
}

func TestEncryptedPayloadRequiresPersistedScopeRevision(t *testing.T) {
	session := validSession()
	envelope := testEnvelope()
	session.Status = StatusWaitingUser
	session.RecipientKeyDigest = digest("c")
	session.PayloadDigest = digest("d")
	session.Envelope = &envelope
	session.AssociatedDataCBOR = []byte{0xa1, 0x01, 0x02}
	if err := session.Validate(); err != ErrInvalid {
		t.Fatalf("envelope without scope revision error = %v, want ErrInvalid", err)
	}
	session.PayloadScopeRevision = session.Revision
	if err := session.Validate(); err != nil {
		t.Fatalf("valid encrypted payload rejected: %v", err)
	}
	cloned := session.Clone()
	cloned.AssociatedDataCBOR[0] ^= 0xff
	cloned.Envelope.Ciphertext = "changed"
	if session.AssociatedDataCBOR[0] != 0xa1 || session.Envelope.Ciphertext == "changed" {
		t.Fatal("session clone aliases encrypted payload state")
	}
}

func TestSessionPersistenceShapeHasNoPlaintextField(t *testing.T) {
	valueType := reflect.TypeOf(SessionV1{})
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"plaintext", "private_key", "recipient_public_key", "password", "bearer_token"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("pairing session persistence field exposes %q: %s", forbidden, name)
			}
		}
	}
}

func TestPayloadReservationStoresOnlyDigestAndHasStableOperationID(t *testing.T) {
	session := validSession()
	digest := digest("c")
	operationID, err := PayloadOperationID(session.SessionID, session.Revision, digest)
	if err != nil {
		t.Fatal(err)
	}
	reservation := PayloadReservationV1{SessionID: session.SessionID, OwnerID: session.OwnerID,
		PayloadScopeRevision: session.Revision, RecipientKeyDigest: digest, OperationID: operationID, CreatedAt: session.CreatedAt}
	if err := reservation.Validate(); err != nil {
		t.Fatalf("valid reservation rejected: %v", err)
	}
	reservationType := reflect.TypeOf(PayloadReservationV1{})
	for index := 0; index < reservationType.NumField(); index++ {
		name := strings.ToLower(reservationType.Field(index).Name + " " + reservationType.Field(index).Tag.Get("json"))
		for _, forbidden := range []string{"recipient_public_key", "plaintext", "private_key", "password"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("reservation persistence field exposes %q: %s", forbidden, name)
			}
		}
	}
	otherScope, err := PayloadOperationID(session.SessionID, session.Revision+1, digest)
	if err != nil || otherScope == operationID {
		t.Fatalf("scope did not fence operation IDs: %q %q err=%v", operationID, otherScope, err)
	}
}

func TestTimedOutSessionMustNotRetainEnvelope(t *testing.T) {
	session := validSession()
	envelope := testEnvelope()
	session.Status = StatusTimedOut
	session.Envelope = &envelope
	session.RecipientKeyDigest, session.PayloadDigest = digest("c"), digest("d")
	session.AssociatedDataCBOR, session.PayloadScopeRevision = []byte{0xa1, 0x01}, session.Revision
	completed := session.ExpiresAt
	session.CompletedAt, session.FailureCode = &completed, "pairing_timed_out"
	if err := session.Validate(); err != ErrInvalid {
		t.Fatalf("expired envelope error = %v, want ErrInvalid", err)
	}
}

func TestMutationRequiresOwnerUUIDIdempotencyAndDigest(t *testing.T) {
	valid := Mutation{OwnerID: "owner-a", IdempotencyKey: uuid.NewString(), RequestDigest: digest("1")}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid mutation rejected: %v", err)
	}
	for _, mutate := range []func(*Mutation){
		func(v *Mutation) { v.OwnerID = "" },
		func(v *Mutation) { v.IdempotencyKey = "retry-1" },
		func(v *Mutation) { v.RequestDigest = digest("g") },
	} {
		value := valid
		mutate(&value)
		if err := value.Validate(); err != ErrInvalid {
			t.Fatalf("invalid mutation error = %v, want ErrInvalid", err)
		}
	}
}

func validSession() SessionV1 {
	now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	return SessionV1{
		SchemaVersion: SchemaV1, SessionID: uuid.NewString(), OwnerID: "owner-a",
		DeploymentID: uuid.NewString(), DeploymentRevision: 1, PlanID: uuid.NewString(), ConnectionID: uuid.NewString(),
		TaskID: uuid.NewString(), StepID: uuid.NewString(),
		RecipeID: "recipe-a", RecipeDigest: digest("a"), RecipeRevision: 3,
		ExecutionManifestDigest: digest("b"),
		BeginCommand:            "pairing.begin", ResumeCommand: "pairing.resume",
		Status: StatusWaitingPayload, ExpiresAt: now.Add(time.Hour), Revision: 1,
		CreatedAt: now, UpdatedAt: now,
	}
}

func testEnvelope() secretbootstrap.RecipientEnvelopeV1 {
	return secretbootstrap.RecipientEnvelopeV1{
		SchemaVersion:   secretbootstrap.RecipientEnvelopeSchemaV1,
		ServerPublicKey: strings.Repeat("A", 43), Nonce: strings.Repeat("B", 16), Ciphertext: strings.Repeat("C", 32),
	}
}

func digest(char string) string { return "sha256:" + strings.Repeat(char, 64) }
