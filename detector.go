package techdetect

import (
	"fmt"
)

// Detector is the main detection engine
type Detector struct {
	httpDetector    *HTTPDetector
	browserDetector *BrowserDetector
	fingerprints    map[string]Fingerprint
	loader          *Loader
}

// NewDetector creates a new detection engine
func NewDetector(fingerprintsDir string) (*Detector, error) {
	return NewDetectorWithOptions(fingerprintsDir, false)
}

// NewDetectorWithOptions creates a new detection engine with custom options
func NewDetectorWithOptions(fingerprintsDir string, insecureSkipVerify bool) (*Detector, error) {
	loader := NewLoader(fingerprintsDir)
	fingerprints, err := loader.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load fingerprints: %w", err)
	}

	return &Detector{
		httpDetector:    NewHTTPDetectorWithOptions(insecureSkipVerify),
		browserDetector: NewBrowserDetector(),
		fingerprints:    fingerprints,
		loader:          loader,
	}, nil
}

// DetectResult contains detection results
type DetectResult struct {
	Technologies []Technology `json:"technologies"`
	FailedPaths  []string     `json:"failed_paths,omitempty"`
}

// Detect performs full detection (HTTP + Browser) on a target URL
func (d *Detector) Detect(url string, useBrowser bool) (*DetectResult, error) {
	// Stage 1: HTTP Detection
	httpResults, failedPaths := d.httpDetector.DetectHTTP(url, d.fingerprints)

	// Stage 2: Browser Detection (optional)
	var finalResults map[string]*Technology
	if useBrowser {
		browserResults, err := d.browserDetector.DetectBrowser(url, d.fingerprints, httpResults)
		if err != nil {
			// Browser detection failed, but we still have HTTP results
			finalResults = httpResults
		} else {
			finalResults = browserResults
		}
	} else {
		finalResults = httpResults
	}

	// Add implied technologies
	finalResults = d.addImpliedTechnologies(finalResults)

	// Convert map to slice
	techs := make([]Technology, 0, len(finalResults))
	for _, tech := range finalResults {
		techs = append(techs, *tech)
	}

	return &DetectResult{
		Technologies: techs,
		FailedPaths:  failedPaths,
	}, nil
}

// addImpliedTechnologies adds technologies that are implied by detected technologies
func (d *Detector) addImpliedTechnologies(results map[string]*Technology) map[string]*Technology {
	// Keep adding implied technologies until no new ones are found
	changed := true
	for changed {
		changed = false
		for techName := range results {
			fp, exists := d.fingerprints[techName]
			if !exists {
				continue
			}

			for _, implied := range fp.Implies {
				if _, alreadyDetected := results[implied]; !alreadyDetected {
					results[implied] = &Technology{
						Name:    implied,
						Version: "", // Implied technologies don't have versions
					}
					changed = true
				}
			}
		}
	}

	return results
}

// DetectHTTPOnly performs HTTP-only detection (fast, no browser)
func (d *Detector) DetectHTTPOnly(url string) (*DetectResult, error) {
	return d.Detect(url, false)
}

// DetectFull performs full detection including browser stage
func (d *Detector) DetectFull(url string) (*DetectResult, error) {
	return d.Detect(url, true)
}
