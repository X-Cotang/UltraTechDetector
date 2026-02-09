package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	techdetect "github.com/X-Cotang/UltraTechDetector"
)

func main() {
	// Command-line flags
	url := flag.String("url", "", "Target URL to analyze (if not provided, reads from stdin)")
	fingerprintsDir := flag.String("fingerprints", "./data/fingerprints", "Path to fingerprints directory")
	useBrowser := flag.Bool("browser", false, "Enable browser detection (slower but more accurate)")
	format := flag.String("format", "text", "Output format: text, json, or jsonl")
	insecure := flag.Bool("insecure", true, "Skip SSL certificate verification (useful for self-signed certs)")

	flag.Parse()

	// Get URLs from either -url flag or positional arguments or stdin
	var urls []string

	// Check if URL is provided as positional argument (after flags)
	if flag.NArg() > 0 {
		urls = flag.Args()
	} else if *url != "" {
		urls = []string{*url}
	} else {
		// Read from stdin (pipe)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := scanner.Err(); err != nil {
			if *format == "text" {
				log.Fatalf("Error reading from stdin: %v", err)
			}
			// For JSON/JSONL, just exit silently
			os.Exit(1)
		}
	}

	if len(urls) == 0 {
		if *format == "text" {
			fmt.Fprintln(os.Stderr, "Usage: techdetect [options] <url> or pipe URLs via stdin")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Examples:")
			fmt.Fprintln(os.Stderr, "  techdetect https://example.com")
			fmt.Fprintln(os.Stderr, "  techdetect -format json https://example.com")
			fmt.Fprintln(os.Stderr, "  echo https://example.com | techdetect -format jsonl")
			fmt.Fprintln(os.Stderr, "  cat urls.txt | techdetect -format jsonl -browser")
			fmt.Fprintln(os.Stderr, "")
			flag.PrintDefaults()
		}
		os.Exit(1)
	}

	// Create detector
	var detector *techdetect.Detector
	var err error
	if *insecure {
		detector, err = techdetect.NewDetectorWithOptions(*fingerprintsDir, true)
	} else {
		detector, err = techdetect.NewDetector(*fingerprintsDir)
	}
	if err != nil {
		if *format == "text" {
			log.Fatalf("Failed to initialize detector: %v", err)
		}
		// For JSON/JSONL, output error in proper format
		if *format == "jsonl" {
			for _, targetURL := range urls {
				scanResult := techdetect.ScanResult{
					URL:          targetURL,
					Technologies: make(map[string]string),
					Mode:         "http",
					Error:        fmt.Sprintf("Failed to initialize detector: %v", err),
				}
				output, _ := json.Marshal(scanResult)
				fmt.Println(string(output))
			}
		} else if *format == "json" {
			results := make([]techdetect.ScanResult, 0)
			for _, targetURL := range urls {
				results = append(results, techdetect.ScanResult{
					URL:          targetURL,
					Technologies: make(map[string]string),
					Mode:         "http",
					Error:        fmt.Sprintf("Failed to initialize detector: %v", err),
				})
			}
			batch := techdetect.BatchResults{Results: results}
			output, _ := json.MarshalIndent(batch, "", "  ")
			fmt.Println(string(output))
		}
		os.Exit(1)
	}

	// Determine mode string
	mode := "http"
	if *useBrowser {
		mode = "hybrid"
	}

	// Process URLs and collect results
	var batchResults []techdetect.ScanResult

	for _, targetURL := range urls {
		// Perform detection
		var result *techdetect.DetectResult
		var scanErr error

		if *useBrowser {
			result, scanErr = detector.DetectFull(targetURL)
		} else {
			result, scanErr = detector.DetectHTTPOnly(targetURL)
		}

		// Convert to ScanResult format
		technologies := make(map[string]string)
		var errorMsg string

		if scanErr != nil {
			errorMsg = scanErr.Error()
		} else if result != nil {
			for _, tech := range result.Technologies {
				technologies[tech.Name] = tech.Version
			}
		}

		scanResult := techdetect.ScanResult{
			URL:          targetURL,
			Technologies: technologies,
			Mode:         mode,
			Error:        errorMsg,
		}

		batchResults = append(batchResults, scanResult)

		// For JSONL, output immediately
		if *format == "jsonl" {
			output, err := json.Marshal(scanResult)
			if err != nil {
				// Should never happen, but handle gracefully
				continue
			}
			fmt.Println(string(output))
		}
	}

	// Output results based on format
	switch *format {
	case "json":
		batch := techdetect.BatchResults{
			Results: batchResults,
		}
		output, err := json.MarshalIndent(batch, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(output))

	case "jsonl":
		// Already output during processing
		// Do nothing here

	case "text":
		fallthrough
	default:
		// Human-readable output
		for _, scanResult := range batchResults {
			if scanResult.Error != "" {
				fmt.Printf("\n❌ %s - Error: %s\n", scanResult.URL, scanResult.Error)
			} else {
				fmt.Printf("\n🔍 %s - Detected %d technologies:\n\n", scanResult.URL, len(scanResult.Technologies))
				for name, version := range scanResult.Technologies {
					if version != "" {
						fmt.Printf("  ✓ %s (v%s)\n", name, version)
					} else {
						fmt.Printf("  ✓ %s\n", name)
					}
				}
			}
		}
		fmt.Println()
	}
}
