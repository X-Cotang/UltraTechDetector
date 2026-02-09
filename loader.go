package techdetect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Loader handles loading fingerprints from disk
type Loader struct {
	fingerprintsDir string
}

// NewLoader creates a new fingerprint loader
func NewLoader(fingerprintsDir string) *Loader {
	return &Loader{
		fingerprintsDir: fingerprintsDir,
	}
}

// LoadAll loads all fingerprints from the fingerprints directory
func (l *Loader) LoadAll() (map[string]Fingerprint, error) {
	allFingerprints := make(map[string]Fingerprint)

	// Read all JSON files in fingerprints directory
	files, err := filepath.Glob(filepath.Join(l.fingerprintsDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list fingerprint files: %w", err)
	}

	for _, file := range files {
		fingerprints, err := l.loadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", file, err)
		}

		// Merge fingerprints
		for name, fp := range fingerprints {
			allFingerprints[name] = fp
		}
	}

	return allFingerprints, nil
}

// loadFile loads fingerprints from a single JSON file
func (l *Loader) loadFile(path string) (map[string]Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var db FingerprintDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	return db.Apps, nil
}
