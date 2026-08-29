//go:build !darwin && !linux

package cache

import "os"

func ownershipChecksSupported() bool {
	return false
}

func ownedByCurrentUser(_ os.FileInfo) bool {
	return false
}

func lockFile(_ *os.File, _ bool) error {
	return ErrUnsupportedPlatform
}

func unlockFile(_ *os.File) error {
	return ErrUnsupportedPlatform
}
