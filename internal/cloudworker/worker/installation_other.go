//go:build !unix

package worker

func verifyOwnedPath(string, string, uint32, bool) error { return ErrInvalid }
