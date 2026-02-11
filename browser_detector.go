package techdetect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserDetector performs browser-based detection
type BrowserDetector struct {
	timeout  time.Duration
	proxyURL string
}

// NewBrowserDetector creates a new browser detector
func NewBrowserDetector() *BrowserDetector {
	return NewBrowserDetectorWithOptions("")
}

// NewBrowserDetectorWithOptions creates a new browser detector with proxy support
func NewBrowserDetectorWithOptions(proxyURL string) *BrowserDetector {
	return &BrowserDetector{
		timeout:  30 * time.Second,
		proxyURL: proxyURL,
	}
}

// BrowserPathClassification groups browser probes by path
type BrowserPathClassification struct {
	Path         string
	Technologies map[string][]BrowserProbe // tech name -> probes
}

// ClassifyBrowserByPath groups browser fingerprints by path
func ClassifyBrowserByPath(fingerprints map[string]Fingerprint) []BrowserPathClassification {
	pathMap := make(map[string]*BrowserPathClassification)

	for techName, fp := range fingerprints {
		for _, probe := range fp.Browser {
			key := probe.Path
			if _, exists := pathMap[key]; !exists {
				pathMap[key] = &BrowserPathClassification{
					Path:         probe.Path,
					Technologies: make(map[string][]BrowserProbe),
				}
			}
			pathMap[key].Technologies[techName] = append(pathMap[key].Technologies[techName], probe)
		}
	}

	// Convert map to slice
	result := make([]BrowserPathClassification, 0, len(pathMap))
	for _, pc := range pathMap {
		result = append(result, *pc)
	}

	return result
}

// ShouldRunBrowserDetection determines if browser detection should run for a technology
func ShouldRunBrowserDetection(techName string, results map[string]*Technology, probe BrowserProbe) bool {
	tech, exists := results[techName]

	// Not detected at all? Run if probe has detection capability
	if !exists {
		return probe.HasDetectionCapability()
	}

	// Already have version? Skip
	if tech.Version != "" {
		return false
	}

	// Detected but no version - only run if probe can extract version
	return probe.HasVersionCapability()
}

// DetectBrowser performs browser-based detection
func (bd *BrowserDetector) DetectBrowser(baseURL string, fingerprints map[string]Fingerprint, httpResults map[string]*Technology) (map[string]*Technology, error) {
	results := make(map[string]*Technology)

	// Copy existing HTTP results
	for k, v := range httpResults {
		results[k] = v
	}

	// Classify browser probes by path
	pathClassifications := ClassifyBrowserByPath(fingerprints)
	if len(pathClassifications) == 0 {
		return results, nil
	}

	// Create browser context with options to suppress errors
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-web-security", true),
	)

	// Add proxy configuration if provided
	if bd.proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(bd.proxyURL))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// Create context with custom logger to suppress chromedp errors
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(format string, v ...interface{}) {
		// Suppress all chromedp logs
	}))
	defer cancel()

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, bd.timeout)
	defer cancel()

	// Process each unique path
	for _, classification := range pathClassifications {
		fullURL := strings.TrimSuffix(baseURL, "/") + classification.Path

		// Navigate to the page
		if err := chromedp.Run(ctx, chromedp.Navigate(fullURL)); err != nil {
			continue // Skip this path on error
		}

		// Wait for page to load
		if err := chromedp.Run(ctx, chromedp.WaitReady("body")); err != nil {
			continue
		}

		// Check all technologies for this path
		for techName, probes := range classification.Technologies {
			for _, probe := range probes {
				// Check if we should run this probe
				if !ShouldRunBrowserDetection(techName, results, probe) {
					continue
				}

				detected := false
				version := ""

				// Run detection script if present
				if probe.Detection != "" {
					var result bool
					script := fmt.Sprintf("(function(){ %s })()", probe.Detection)
					if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err == nil {
						detected = result
					}
				}

				// Run version extraction script if needed
				if detected || (results[techName] != nil && probe.Version != "") {
					if probe.Version != "" {
						var versionResult string
						script := fmt.Sprintf("(function(){ %s })()", probe.Version)
						if err := chromedp.Run(ctx, chromedp.Evaluate(script, &versionResult)); err == nil {
							version = versionResult
						}
					}
				}

				// Update results
				if detected {
					if _, exists := results[techName]; !exists {
						results[techName] = &Technology{
							Name:    techName,
							Version: version,
						}
					} else if version != "" && results[techName].Version == "" {
						// Update version if found and not already set
						results[techName].Version = version
					}
					break // Found, no need to check other probes
				} else if version != "" && results[techName] != nil && results[techName].Version == "" {
					// Update version even if not detected (tech already detected in HTTP stage)
					results[techName].Version = version
					break
				}
			}
		}
	}

	return results, nil
}
