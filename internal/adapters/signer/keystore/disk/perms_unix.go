//go:build unix || darwin || linux

package disk

import (
	"fmt"
	"os"
)

// enforceStrictKeyPerms ensures the key file is not group/world readable or writable.
// Allowed: 0400, 0600 (owner read/write). Deny if any group/other bits set.
func enforceStrictKeyPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	// if any group/other bits are set, reject
	if mode&(0o077) != 0 {
		return fmt.Errorf("insecure permissions on %s: %o (require 0600 or 0400)", path, mode)
	}
	return nil
}
