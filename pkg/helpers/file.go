package helpers

import (
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFile is a convenience method for writing data to a filesystem
func WriteFile(path string, data []byte, perm fs.FileMode) error {
	dir, _ := filepath.Split(path)
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, perm)
	if err != nil {
		return err
	}
	return nil
}
