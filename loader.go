package techdetect

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed data/fingerprints/*.json
var embeddedFingerprints embed.FS

// Loader handles loading fingerprints from disk or embedded FS
type Loader struct {
	fingerprintsDir string
	useEmbedded     bool
}

// NewLoader creates a new fingerprint loader that uses embedded fingerprints
func NewLoader(fingerprintsDir string) *Loader {
	// If fingerprintsDir is empty or default, use embedded
	useEmbedded := fingerprintsDir == "" || fingerprintsDir == "./data/fingerprints"
	return &Loader{
		fingerprintsDir: fingerprintsDir,
		useEmbedded:     useEmbedded,
	}
}

// LoadAll loads all fingerprints from either embedded FS or external directory
func (l *Loader) LoadAll() (map[string]Fingerprint, error) {
	allFingerprints := make(map[string]Fingerprint)

	if l.useEmbedded {
		// Load from embedded filesystem
		pattern := "data/fingerprints/*.json"
		files, err := fs.Glob(embeddedFingerprints, pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to list embedded fingerprint files: %w", err)
		}

		for _, file := range files {
			fingerprints, err := l.loadEmbeddedFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load embedded %s: %w", file, err)
			}

			// Merge fingerprints
			for name, fp := range fingerprints {
				allFingerprints[name] = fp
			}
		}
	} else {
		// Load from external directory
		files, err := filepath.Glob(filepath.Join(l.fingerprintsDir, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("failed to list fingerprint files: %w", err)
		}

		for _, file := range files {
			fingerprints, err := l.loadExternalFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load %s: %w", file, err)
			}

			// Merge fingerprints
			for name, fp := range fingerprints {
				allFingerprints[name] = fp
			}
		}
	}

	return allFingerprints, nil
}

// loadEmbeddedFile loads fingerprints from an embedded JSON file
func (l *Loader) loadEmbeddedFile(path string) (map[string]Fingerprint, error) {
	data, err := embeddedFingerprints.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var db FingerprintDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	return db.Apps, nil
}

// loadExternalFile loads fingerprints from an external JSON file
func (l *Loader) loadExternalFile(path string) (map[string]Fingerprint, error) {
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
