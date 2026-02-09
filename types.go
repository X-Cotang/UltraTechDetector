package techdetect

// Technology represents a detected technology
type Technology struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanResult represents the result for a single URL in JSON/JSONL format
type ScanResult struct {
	URL          string            `json:"url"`
	Technologies map[string]string `json:"technologies"`    // tech name -> version
	Mode         string            `json:"mode"`            // "http", "browser", or "hybrid"
	Error        string            `json:"error,omitempty"` // error message if scan failed
}

// BatchResults wraps multiple scan results for JSON array output
type BatchResults struct {
	Results []ScanResult `json:"results"`
}

// Fingerprint represents the detection rules for a technology
type Fingerprint struct {
	Cats        []int          `json:"cats"`
	Implies     []string       `json:"implies,omitempty"`
	Paths       []PathProbe    `json:"paths,omitempty"`
	Browser     []BrowserProbe `json:"browser,omitempty"`
	Description string         `json:"description,omitempty"`
	Website     string         `json:"website,omitempty"`
	Icon        string         `json:"icon,omitempty"`
	CPE         string         `json:"cpe,omitempty"`
}

// PathProbe represents an HTTP-based detection probe
type PathProbe struct {
	Path           string                 `json:"path"`
	Request        *RequestConfig         `json:"request,omitempty"`
	Detect         map[string]interface{} `json:"detect"`
	ExtractVersion []map[string]string    `json:"extract_version,omitempty"`
}

// RequestConfig represents optional HTTP request configuration
type RequestConfig struct {
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    interface{}       `json:"body,omitempty"`
}

// BrowserProbe represents a browser-based detection probe
type BrowserProbe struct {
	Path      string `json:"path"`
	Detection string `json:"detection,omitempty"`
	Version   string `json:"version,omitempty"`
}

// FingerprintDB represents the entire fingerprint database
type FingerprintDB struct {
	Apps map[string]Fingerprint `json:"apps"`
}

// DetectionContext holds data available for detection
type DetectionContext struct {
	Body       string
	Headers    map[string]string
	StatusCode int
}

// HasDetectionCapability checks if browser probe can detect technology
func (bp *BrowserProbe) HasDetectionCapability() bool {
	return bp.Detection != ""
}

// HasVersionCapability checks if browser probe can extract version
func (bp *BrowserProbe) HasVersionCapability() bool {
	return bp.Version != ""
}
