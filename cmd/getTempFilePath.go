package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

func GetTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}
