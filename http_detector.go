package techdetect

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

const (
	MaxRetries     = 1
	RequestTimeout = 10 * time.Second
	MaxRedirects   = 3
	InitialBackoff = 1 * time.Second
)

// HTTPDetector performs HTTP-based detection
type HTTPDetector struct {
	client    *http.Client
	evaluator *QueryEvaluator
}

// NewHTTPDetector creates a new HTTP detector
func NewHTTPDetector() *HTTPDetector {
	return NewHTTPDetectorWithOptions(false)
}

// NewHTTPDetectorWithOptions creates a new HTTP detector with custom options
func NewHTTPDetectorWithOptions(insecureSkipVerify bool) *HTTPDetector {
	// Create custom transport if needed
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	}

	return &HTTPDetector{
		client: &http.Client{
			Timeout:   RequestTimeout,
			Transport: transport,
			// Disable automatic redirects - we'll handle them manually
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		evaluator: NewQueryEvaluator(),
	}
}

// PathClassification groups fingerprints by path
type PathClassification struct {
	Path         string
	RequestConf  *RequestConfig
	Technologies map[string][]PathProbe // tech name -> probes
}

// ClassifyByPath groups all fingerprints by their request paths
func ClassifyByPath(fingerprints map[string]Fingerprint) []PathClassification {
	pathMap := make(map[string]*PathClassification)

	for techName, fp := range fingerprints {
		for _, probe := range fp.Paths {
			key := probe.Path
			if _, exists := pathMap[key]; !exists {
				pathMap[key] = &PathClassification{
					Path:         probe.Path,
					RequestConf:  probe.Request,
					Technologies: make(map[string][]PathProbe),
				}
			}
			pathMap[key].Technologies[techName] = append(pathMap[key].Technologies[techName], probe)
		}
	}

	// Convert map to slice
	result := make([]PathClassification, 0, len(pathMap))
	for _, pc := range pathMap {
		result = append(result, *pc)
	}

	return result
}

// DetectHTTP performs HTTP-based detection on a target URL
func (hd *HTTPDetector) DetectHTTP(baseURL string, fingerprints map[string]Fingerprint) (map[string]*Technology, []string) {
	results := make(map[string]*Technology)
	failedPaths := []string{}

	// Classify fingerprints by path
	pathClassifications := ClassifyByPath(fingerprints)

	// Process each unique path
	for _, classification := range pathClassifications {
		fullURL := strings.TrimSuffix(baseURL, "/") + classification.Path

		// Make HTTP request with retry logic
		ctx, err := hd.requestWithRetry(fullURL, classification.RequestConf)
		if err != nil {
			failedPaths = append(failedPaths, classification.Path)

			// Check for fatal network errors that mean we should stop trying other paths
			errStr := err.Error()
			if strings.Contains(errStr, "no such host") ||
				strings.Contains(errStr, "network is unreachable") {
				// Mark all remaining paths as failed and break
				for _, remainingClass := range pathClassifications {
					alreadyFailed := false
					for _, fp := range failedPaths {
						if fp == remainingClass.Path {
							alreadyFailed = true
							break
						}
					}
					if !alreadyFailed {
						failedPaths = append(failedPaths, remainingClass.Path)
					}
				}
				break
			}
			continue
		}

		// Check all technologies for this path
		for techName, probes := range classification.Technologies {
			for _, probe := range probes {
				detected, version := hd.evaluator.Evaluate(probe.Detect, ctx)
				if detected {
					// Try to extract version if not already found
					if version == "" && len(probe.ExtractVersion) > 0 {
						version = hd.evaluator.ExtractVersion(probe.ExtractVersion, ctx)
					}

					results[techName] = &Technology{
						Name:    techName,
						Version: version,
					}
					break // Found, no need to check other probes for this tech
				}
			}
		}
	}

	return results, failedPaths
}

// requestWithRetry makes an HTTP request with retry logic
func (hd *HTTPDetector) requestWithRetry(url string, reqConfig *RequestConfig) (*DetectionContext, error) {
	var lastErr error

	for retry := 0; retry <= MaxRetries; retry++ {
		ctx, err := hd.makeRequest(url, reqConfig)
		if err == nil {
			return ctx, nil
		}

		lastErr = err

		// Don't retry on last attempt
		if retry < MaxRetries {
			// Exponential backoff
			backoff := InitialBackoff * time.Duration(math.Pow(2, float64(retry)))
			time.Sleep(backoff)
		}
	}

	return nil, fmt.Errorf("failed after %d retries: %w", MaxRetries, lastErr)
}

// makeRequest performs HTTP request with manual redirect handling
func (hd *HTTPDetector) makeRequest(url string, reqConfig *RequestConfig) (*DetectionContext, error) {
	currentURL := url
	redirectCount := 0

	// Accumulate all bodies and headers from redirect chain
	var allBodies []string
	allHeaders := make(map[string]string)

	for {
		method := "GET"
		var body io.Reader

		if reqConfig != nil {
			if reqConfig.Method != "" {
				method = reqConfig.Method
			}
		}

		req, err := http.NewRequest(method, currentURL, body)
		if err != nil {
			return nil, err
		}

		// Add custom headers
		if reqConfig != nil && reqConfig.Headers != nil {
			for k, v := range reqConfig.Headers {
				req.Header.Set(k, v)
			}
		}

		// Make request
		resp, err := hd.client.Do(req)
		if err != nil {
			return nil, err
		}

		// Read response body
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		// Collect headers from this response
		for k, v := range resp.Header {
			if len(v) > 0 {
				// Keep first occurrence of each header
				if _, exists := allHeaders[k]; !exists {
					allHeaders[k] = v[0]
				}
			}
		}

		// Collect body from this response
		if len(bodyBytes) > 0 {
			allBodies = append(allBodies, string(bodyBytes))
		}

		// Check if this is a redirect (3xx status code)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Get redirect location
			location := resp.Header.Get("Location")
			if location == "" {
				// No location header, stop here
				break
			}

			// Check redirect limit
			if redirectCount >= MaxRedirects {
				// Reached max redirects, stop here
				break
			}

			// Parse current URL and redirect location
			currentURLParsed, err := parseURL(currentURL)
			if err != nil {
				break
			}

			// Resolve relative redirect URLs
			redirectURL, err := resolveURL(currentURL, location)
			if err != nil {
				break
			}

			redirectURLParsed, err := parseURL(redirectURL)
			if err != nil {
				break
			}

			// Check if same domain (different port is OK)
			if !isSameDomain(currentURLParsed, redirectURLParsed) {
				// Different domain, stop following redirects
				break
			}

			// Follow the redirect
			currentURL = redirectURL
			redirectCount++
			continue
		}

		// Not a redirect, stop here
		break
	}

	// Combine all bodies (concatenate)
	combinedBody := strings.Join(allBodies, "\n")

	return &DetectionContext{
		Body:       combinedBody,
		Headers:    allHeaders,
		StatusCode: 200, // We successfully got responses
	}, nil
}

// Helper functions for URL parsing and comparison

func parseURL(urlStr string) (map[string]string, error) {
	// Simple URL parser - extract scheme, host, port
	parts := make(map[string]string)

	// Extract scheme
	schemeEnd := strings.Index(urlStr, "://")
	if schemeEnd == -1 {
		return nil, fmt.Errorf("invalid URL: no scheme")
	}
	parts["scheme"] = urlStr[:schemeEnd]

	// Extract host and port
	rest := urlStr[schemeEnd+3:]
	slashIdx := strings.Index(rest, "/")
	var hostPort string
	if slashIdx == -1 {
		hostPort = rest
	} else {
		hostPort = rest[:slashIdx]
	}

	// Split host and port
	colonIdx := strings.LastIndex(hostPort, ":")
	if colonIdx != -1 {
		parts["host"] = hostPort[:colonIdx]
		parts["port"] = hostPort[colonIdx+1:]
	} else {
		parts["host"] = hostPort
		// Default ports
		if parts["scheme"] == "https" {
			parts["port"] = "443"
		} else {
			parts["port"] = "80"
		}
	}

	return parts, nil
}

func resolveURL(base, relative string) (string, error) {
	// If relative URL starts with http:// or https://, it's absolute
	if strings.HasPrefix(relative, "http://") || strings.HasPrefix(relative, "https://") {
		return relative, nil
	}

	// If starts with //, use same scheme as base
	if strings.HasPrefix(relative, "//") {
		baseParts, err := parseURL(base)
		if err != nil {
			return "", err
		}
		return baseParts["scheme"] + ":" + relative, nil
	}

	// If starts with /, it's absolute path
	if strings.HasPrefix(relative, "/") {
		// Extract scheme://host:port from base
		schemeEnd := strings.Index(base, "://")
		if schemeEnd == -1 {
			return "", fmt.Errorf("invalid base URL")
		}
		rest := base[schemeEnd+3:]
		slashIdx := strings.Index(rest, "/")
		var basePrefix string
		if slashIdx == -1 {
			basePrefix = base
		} else {
			basePrefix = base[:schemeEnd+3+slashIdx]
		}
		return basePrefix + relative, nil
	}

	// Relative path - join with base path
	// For simplicity, just append to base
	if strings.HasSuffix(base, "/") {
		return base + relative, nil
	}
	return base + "/" + relative, nil
}

func isSameDomain(url1, url2 map[string]string) bool {
	// Compare host (case-insensitive)
	return strings.EqualFold(url1["host"], url2["host"])
}
