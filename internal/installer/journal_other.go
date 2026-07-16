//go:build !linux

package installer

import "runtime"

func validateRootOwnedJournalParent(string) error {
	return errorf(CodeJournalUnavailable, "root-owned execution journal is unsupported on %s", runtime.GOOS)
}

func validateRootOwnedJournalFile(string) error {
	return errorf(CodeJournalUnavailable, "root-owned execution journal is unsupported on %s", runtime.GOOS)
}
