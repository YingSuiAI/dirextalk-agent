package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.Error("AWS reaper capability is not enabled in this build")
	os.Exit(78)
}
