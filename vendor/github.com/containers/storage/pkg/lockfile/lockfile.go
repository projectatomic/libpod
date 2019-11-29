package lockfile

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// A Locker represents a file lock where the file is used to cache an
// identifier of the last party that made changes to whatever's being protected
// by the lock.
type Locker interface {
	// Acquire a writer lock.
	Lock()

	// Acquire a writer lock recursively, allowing for recursive acquisitions
	// within the same process space.
	RecursiveLock()

	// Unlock the lock.
	Unlock()

	// Acquire a reader lock.
	RLock()

	// Touch records, for others sharing the lock, that the caller was the
	// last writer.  It should only be called with the lock held.
	Touch() error

	// Modified() checks if the most recent writer was a party other than the
	// last recorded writer.  It should only be called with the lock held.
	Modified() (bool, error)

	// TouchedSince() checks if the most recent writer modified the file (likely using Touch()) after the specified time.
	TouchedSince(when time.Time) bool

	// IsReadWrite() checks if the lock file is read-write
	IsReadWrite() bool

	// Locked() checks if lock is locked for writing by a thread in this process
	Locked() bool

	// SetReadOnly can be used to set the locker either to `read-only` or
	// `read-write`
	SetReadOnly(bool)
}

var (
	lockfiles     map[string]Locker
	lockfilesLock sync.Mutex
)

// GetLockfile opens a read-write lock file, creating it if necessary.  The
// Locker object may already be locked if the path has already been requested
// by the current process.
func GetLockfile(path string) (Locker, error) {
	return getLockfile(path, false, false)
}

// GetROLockfile opens a read-only lock file, creating it if necessary.  The
// Locker object may already be locked if the path has already been requested
// by the current process.
func GetROLockfile(path string) (Locker, error) {
	return getLockfile(path, true, false)
}

// GetLockfileRWRO opens a read-only or read-write lock file, depending on its
// use. The Locker object may already be locked if the path has already been
// requested by the current process.
func GetLockfileRWRO(path string, readOnly bool) (Locker, error) {
	return getLockfile(path, readOnly, true)
}

// getLockfile returns a Locker object, possibly (depending on the platform)
// working inter-process, and associated with the specified path.
//
// If ro, the lock is a read-write lock and the returned Locker should correspond to the
// “lock for reading” (shared) operation; otherwise, the lock is either an exclusive lock,
// or a read-write lock and Locker should correspond to the “lock for writing” (exclusive) operation.
//
// `overWriteReadOnly` indicates if the locker should be used as universal
// `read-write` and `read-only` lock.  If `overWriteReadOnly` is false, then
// the function will fail if the locker does not match its desired state.
//
// WARNING:
// - The lock may or MAY NOT be inter-process.
// - There may or MAY NOT be an actual object on the filesystem created for the specified path.
// - Even if ro, the lock MAY be exclusive.
func getLockfile(path string, ro, overWriteReadOnly bool) (Locker, error) {
	lockfilesLock.Lock()
	defer lockfilesLock.Unlock()
	if lockfiles == nil {
		lockfiles = make(map[string]Locker)
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.Wrapf(err, "error ensuring that path %q is an absolute path", path)
	}
	if locker, ok := lockfiles[cleanPath]; ok {
		if overWriteReadOnly {
			locker.SetReadOnly(ro)
		}
		if ro && locker.IsReadWrite() {
			return nil, errors.Errorf("lock %q is not a read-only lock", cleanPath)
		}
		if !ro && !locker.IsReadWrite() {
			return nil, errors.Errorf("lock %q is not a read-write lock", cleanPath)
		}
		return locker, nil
	}
	locker, err := createLockerForPath(cleanPath, ro) // platform-dependent locker
	if err != nil {
		return nil, err
	}
	lockfiles[cleanPath] = locker
	return locker, nil
}
