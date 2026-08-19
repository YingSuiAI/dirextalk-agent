package sshworker

import (
	"context"
	"testing"
	"time"
)

func TestWorkerDisplayNameAndCreatedAtPersistAndProjectWhenUnavailable(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	record := WorkerRecord{WorkerID: "worker-one", OwnerID: "owner", AccountGeneration: 7,
		Credential:  CredentialIdentity{CredentialID: "credential-one", CredentialRevision: 2, AccountID: "123456789012", Region: "ap-east-1"},
		DisplayName: "构建服务器", Phase: WorkerIdle, CreatedAt: createdAt, UpdatedAt: createdAt}
	if err = store.SaveWorker(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadWorker(context.Background(), record.WorkerID)
	if err != nil || !found {
		t.Fatalf("LoadWorker() = %#v, %v, %v", loaded, found, err)
	}
	status := UnavailableStatus(loaded, createdAt.Add(time.Minute), "credential unavailable")
	if status.DisplayName != record.DisplayName || !status.CreatedAt.Equal(createdAt) {
		t.Fatalf("status = %#v", status)
	}
}
