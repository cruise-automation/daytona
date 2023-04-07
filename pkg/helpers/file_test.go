package helpers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileParents(t *testing.T) {
	parentDir := os.TempDir()
	td, err := os.MkdirTemp(parentDir, "*-iykyk")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(td)

	err = WriteFile(filepath.Join(td, "levelone", "leveltwo", "test.log"), []byte("hi there"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = WriteFile(filepath.Join(td, "test.log"), []byte("helllo there"), 0600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteFile(t *testing.T) {
	tf, err := os.CreateTemp("", "*-iykyk")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tf.Name())

	err = WriteFile(tf.Name(), []byte("hey there"), 0600)
	if err != nil {
		t.Fatal(err)
	}
}
