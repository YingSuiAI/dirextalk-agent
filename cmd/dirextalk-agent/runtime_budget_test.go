package main

import (
	"runtime/debug"
	"testing"
)

func TestApplyGoMemoryLimitUsesConfiguredBoundAndRestoresPreviousValue(t *testing.T) {
	original := debug.SetMemoryLimit(1024 * 1024 * 1024)
	defer debug.SetMemoryLimit(original)

	effective, restore, err := applyGoMemoryLimit(768 * 1024 * 1024)
	if err != nil || effective != 768*1024*1024 || restore == nil {
		t.Fatalf("effective=%d restore_nil=%t error=%v", effective, restore == nil, err)
	}
	if got := debug.SetMemoryLimit(-1); got != effective {
		t.Fatalf("runtime memory limit=%d want=%d", got, effective)
	}
	restore()
	if got := debug.SetMemoryLimit(-1); got != 1024*1024*1024 {
		t.Fatalf("restored memory limit=%d", got)
	}
}

func TestApplyGoMemoryLimitNeverRaisesStricterExistingBound(t *testing.T) {
	original := debug.SetMemoryLimit(512 * 1024 * 1024)
	defer debug.SetMemoryLimit(original)

	effective, restore, err := applyGoMemoryLimit(768 * 1024 * 1024)
	if err != nil || effective != 512*1024*1024 {
		t.Fatalf("effective=%d error=%v", effective, err)
	}
	restore()
}
