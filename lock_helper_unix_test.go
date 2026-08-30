//go:build darwin || linux

package main_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func startCacheLockHolder(t *testing.T, lockPath string) *exec.Cmd {
	t.Helper()

	readyPath := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestCacheLockHelper$")
	command.Env = append(os.Environ(),
		"SECRETS_CACHE_LOCK_HELPER=1",
		"SECRETS_CACHE_LOCK_PATH="+lockPath,
		"SECRETS_CACHE_LOCK_READY="+readyPath,
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatalf("start cache lock holder: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			return command
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("cache lock holder did not acquire the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func stopCacheLockHolder(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("stop cache lock holder: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("cache lock holder exited successfully after termination")
	}
}

func TestCacheLockHelper(t *testing.T) {
	if os.Getenv("SECRETS_CACHE_LOCK_HELPER") != "1" {
		return
	}

	lock, err := os.OpenFile(os.Getenv("SECRETS_CACHE_LOCK_PATH"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("SECRETS_CACHE_LOCK_READY"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}
