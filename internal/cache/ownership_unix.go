//go:build darwin || linux

package cache

import (
	"os"
	"syscall"
)

func ownershipChecksSupported() bool {
	return true
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func tryLockFile(file *os.File, exclusive bool) (bool, error) {
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func unlockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
