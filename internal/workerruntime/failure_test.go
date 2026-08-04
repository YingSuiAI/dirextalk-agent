package workerruntime

import "testing"

func requireFailure(
	t *testing.T,
	err error,
	code FailureCode,
	stage FailureStage,
) {
	t.Helper()
	failure, ok := FailureOf(err)
	if !ok {
		t.Fatalf("error has no typed failure: %v", err)
	}
	if failure.Code != code || failure.Stage != stage {
		t.Fatalf("failure = %+v, want code=%s stage=%s", failure, code, stage)
	}
}
