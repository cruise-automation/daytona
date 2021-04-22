package helpers

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
)

func WriteFile(path string, data []byte, perm fs.FileMode) error {
	dir, _ := filepath.Split(path)
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, data, perm)
	if err != nil {
		return err
	}
	return nil
}