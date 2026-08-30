//go:build !darwin && !linux

package main_test

import (
	"os/exec"
	"testing"
)

func startCacheLockHolder(t *testing.T, _ string) *exec.Cmd {
	t.Helper()
	t.Skip("cache locking is supported on macOS and Linux")
	return nil
}

func stopCacheLockHolder(t *testing.T, _ *exec.Cmd) {
	t.Helper()
}
