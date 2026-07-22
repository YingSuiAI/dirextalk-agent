package main

import (
	"errors"
	"runtime/debug"
)

func applyGoMemoryLimit(configured int64) (int64, func(), error) {
	if configured <= 0 {
		return 0, nil, errors.New("Go memory limit must be positive")
	}
	current := debug.SetMemoryLimit(-1)
	effective := configured
	if current > 0 && current < effective {
		effective = current
	}
	previous := debug.SetMemoryLimit(effective)
	return effective, func() { debug.SetMemoryLimit(previous) }, nil
}
