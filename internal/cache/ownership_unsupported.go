//go:build !darwin && !linux

package cache

import "os"

func ownershipChecksSupported() bool {
	return false
}

func ownedByCurrentUser(_ os.FileInfo) bool {
	return false
}

func tryLockFile(_ *os.File, _ bool) (bool, error) {
	return false, ErrUnsupportedPlatform
}

func unlockFile(_ *os.File) error {
	return ErrUnsupportedPlatform
}
