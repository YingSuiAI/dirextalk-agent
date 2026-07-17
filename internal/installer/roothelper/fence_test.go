package roothelper

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestDeliveryFencePersistsAndSyncsEveryAcceptedBindingRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery-fence.cbor")
	syncCalls := 0
	fence, err := openDeliveryFenceWithSync(path, false, func(parent string) error {
		if parent != filepath.Dir(path) {
			t.Fatalf("synced wrong parent: %s", parent)
		}
		syncCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	value := DeliveryFenceValue{
		SchemaVersion: DeliveryFenceSchemaV1, DeploymentID: uuid.NewString(),
		DeliveryID: uuid.NewString(), BindingRevision: 1,
		PublicKeyDigest: digest('a'),
	}
	if err := fence.Accept(context.Background(), value); err != nil || syncCalls != 1 {
		t.Fatalf("first accept err=%v sync_calls=%d", err, syncCalls)
	}
	if err := fence.Accept(context.Background(), value); err != nil || syncCalls != 1 {
		t.Fatalf("exact replay rewrote fence: err=%v sync_calls=%d", err, syncCalls)
	}
	value.BindingRevision = 2
	value.DeliveryID = uuid.NewString()
	value.PublicKeyDigest = digest('c')
	if err := fence.Accept(context.Background(), value); err != nil || syncCalls != 2 {
		t.Fatalf("advance err=%v sync_calls=%d", err, syncCalls)
	}
	rollback := value
	rollback.BindingRevision = 1
	rollback.DeliveryID = uuid.NewString()
	if err := fence.Accept(context.Background(), rollback); err != ErrUnauthorized {
		t.Fatalf("binding rollback error = %v", err)
	}
	reopened, err := openDeliveryFence(path, false)
	if err != nil || reopened.Match(context.Background(), value) != nil {
		t.Fatalf("reopen lost fence: err=%v", err)
	}
}
