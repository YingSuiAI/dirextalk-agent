package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/google/uuid"
)

func TestCoreExecutionV2PostgresListBindsFirstPageFiltersAndCursor(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	records, err := coreexecutionv2.NewPostgresStore(store.Pool())
	if err != nil {
		t.Fatal(err)
	}
	const owner = "@owner:example.test"

	empty, next, err := records.List(ctx, owner, "target", nil, "", 50)
	if err != nil || len(empty) != 0 || next != "" {
		t.Fatalf("empty first page = %#v, next %q, err %v", empty, next, err)
	}

	projectA, projectB := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, fixture := range []struct {
		kind      string
		projectID string
	}{
		{kind: "target", projectID: projectA},
		{kind: "plan", projectID: projectA},
		{kind: "deployment", projectID: projectA},
		{kind: "deployment", projectID: projectB},
		{kind: "binding", projectID: projectA},
	} {
		id := uuid.NewString()
		if _, err := store.Pool().Exec(ctx, `INSERT INTO core_execution_v2_records(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at) VALUES($1,$2,$3,1,'ready',$4,jsonb_build_object('project_id',$5::text),$6,$6)`, owner, fixture.kind, id, strings.Repeat("a", 64), fixture.projectID, now); err != nil {
			t.Fatal(err)
		}
	}

	for _, fixture := range []struct {
		kind  string
		count int
	}{
		{kind: "target", count: 1},
		{kind: "plan", count: 1},
		{kind: "deployment", count: 2},
		{kind: "binding", count: 1},
	} {
		items, _, err := records.List(ctx, owner, fixture.kind, nil, "", 50)
		if err != nil || len(items) != fixture.count {
			t.Fatalf("%s first page count = %d, err %v", fixture.kind, len(items), err)
		}
	}

	filtered, _, err := records.List(ctx, owner, "deployment", map[string]string{"project_id": projectA}, "", 50)
	if err != nil || len(filtered) != 1 || filtered[0].Payload["project_id"] != projectA {
		t.Fatalf("filtered deployment page = %#v, err %v", filtered, err)
	}

	first, cursor, err := records.List(ctx, owner, "deployment", nil, "", 1)
	if err != nil || len(first) != 1 || cursor != first[0].ID {
		t.Fatalf("first deployment cursor page = %#v, cursor %q, err %v", first, cursor, err)
	}
	second, _, err := records.List(ctx, owner, "deployment", nil, cursor, 1)
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatalf("second deployment cursor page = %#v, err %v", second, err)
	}
}
