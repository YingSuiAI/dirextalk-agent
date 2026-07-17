//go:build !linux

package roothelper

func validateRootOwnedRestartJournalParent(string) error { return ErrUnavailable }
func validateRootOwnedRestartJournalFile(string) error   { return ErrUnavailable }
