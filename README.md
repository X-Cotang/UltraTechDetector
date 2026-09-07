# TechDetect

A enhanced web technology detection engine inspired by [ProjectDiscovery's wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), featuring improved fingerprint organization, MongoDB-style query evaluation, and browser-based detection capabilities.

## Key Features

- 🎯 **Dual-Stage Detection**: HTTP-based (fast) + Browser-based (accurate) detection
- 🖼️ **Favicon Hash Detection**: Shodan mmh3 and OWASP/WhatWeb MD5 hashes of `/favicon.ico` and HTML icon links
- 📁 **Organized Fingerprints**: Technologies categorized into separate files for easier management
- 📦 **Embedded Fingerprints**: All fingerprints bundled into binary - no external dependencies needed
- 🔍 **MongoDB-Style Queries**: Advanced query evaluation with 9 operators (`$or`, `$and`, `$not`, `$nor`, `$regex`, `$eq`, `$ne`, `$exists`, `$in`, `$nin`) for precise detection and reduced false positives
- 🌐 **Browser Detection**: Chromedp integration for JavaScript execution and accurate version extraction (e.g., Next.js, React)
- 🔄 **Smart Redirect Handling**: Follows same-domain redirects with data accumulation
- 🚀 **Pipeline-Friendly**: Clean JSON/JSONL output for seamless integration with other tools
- 🌐 **Proxy Support**: HTTP and SOCKS5 proxies with authentication
- 🔒 **SSL Options**: Skip verification for self-signed certificates

## Installation

### Option 1: Download Binary (Recommended)

Download the pre-built binary from releases. All fingerprints are embedded - no additional files needed!

```bash
# Just run it
./techdetect https://example.com
```

### Option 2: Build from Source

```bash
git clone <repository-url>
cd wappalyzergo_extra
go mod tidy
go build -o techdetect ./cmd/techdetect
```

## Quick Start

```bash
# Basic HTTP detection
./techdetect https://example.com

# With browser detection
./techdetect -browser https://example.com

# JSON output
./techdetect -format json https://example.com

# JSONL output (streaming)
./techdetect -format jsonl https://example.com

# Skip SSL verification
./techdetect -insecure true https://self-signed.example.com

# Using HTTP proxy
./techdetect -proxy http://proxy.example.com:8080 https://example.com

# Using HTTP proxy with authentication
./techdetect -proxy http://user:pass@proxy.example.com:8080 https://example.com

# Using SOCKS5 proxy
./techdetect -proxy socks5://proxy.example.com:1080 https://example.com

# Using SOCKS5 proxy with authentication
./techdetect -proxy socks5://user:pass@proxy.example.com:1080 https://example.com

# Pipe input from other tools
cat urls.txt | ./techdetect -format jsonl
echo https://example.com | ./techdetect -format json
```

## Output Formats

### Text (Human-Readable)
```
🔍 https://nextjs.org - Detected 11 technologies:

  ✓ Turbopack
  ✓ Next.js (v16.2.0-canary.19)
  ✓ Framer Motion
  ✓ Webpack
  ✓ HSTS
  ✓ Next.js App Router
  ✓ Vercel Speed Insights
  ✓ Node.js
  ✓ Vercel
  ✓ React
  ✓ Vercel Analytics
```

### JSON (Batch)
```json
{
  "results": [
    {
      "url": "https://example.com",
      "technologies": {
        "React": "18.2.0",
        "Next.js": "13.4.0"
      },
      "mode": "http"
    }
  ]
}
```

### JSONL (Streaming)
```json
{"url":"https://example.com","technologies":{"React":"18.2.0"},"mode":"http"}
{"url":"https://another.com","technologies":{"Vue.js":"3.0"},"mode":"http"}
```

## Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL to analyze | - |
| `-format` | Output format: `text`, `json`, or `jsonl` | `text` |
| `-browser` | Enable browser detection (slower but more accurate) | `false` |
| `-insecure` | Skip SSL certificate verification | `false` |
| `-fingerprints` | Path to fingerprints directory | `./data/fingerprints` |
| `-proxy` | Proxy URL (`http://[user:pass@]host:port` or `socks5://[user:pass@]host:port`) | - |

## Integration with ProjectDiscovery Tools

```bash
# Subdomain discovery → Tech detection
subfinder -d target.com | httpx -silent | ./techdetect -format jsonl

# Port scanning → Tech detection
echo target.com | naabu -silent | ./techdetect -format jsonl

# URL probing → Tech detection
cat urls.txt | httpx -silent | ./techdetect -format jsonl -browser
```

## Architecture

```
┌─────────────────────────────────────────┐
│       Technology Detection Engine        │
└─────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────▼────────┐    ┌────────▼────────┐
│  HTTP Detector  │    │ Browser Detector│
│                 │    │                 │
│ • Path classify │    │ • Chromedp      │
│ • Favicon hash  │    │ • JS execution  │
│ • Retry logic   │    │ • Version       │
│ • Query eval    │    │   extraction    │
│ • Redirects     │    │                 │
└────────┬────────┘    └────────┬────────┘
         │                      │
         └──────────┬───────────┘
                    │
         ┌──────────▼──────────┐
         │   Query Evaluator    │
         │                      │
         │ MongoDB-Style:       │
         │ $or, $and, $not,     │
         │ $nor, $regex, $eq,   │
         │ $ne, $exists, $in,   │
         │ $nin                 │
         └─────────────────────┘
```

## Fingerprint Structure

Fingerprints are organized by technology category in `data/fingerprints/`:

```
data/
├── categories.json
└── fingerprints/
    ├── 001-cms.json
    ├── 012-javascript-frameworks.json
    ├── 035-maps.json
    └── ...
```

Each fingerprint supports MongoDB-style queries for precise detection:

```json
{
  "apps": {
    "WordPress": {
      "cats": [1, 11],
      "implies": ["MySQL", "PHP"],
      "paths": [
        {
          "path": "/",
          "detect": {
            "$or": [
              {"body": {"$regex": "/wp-content/"}},
              {"headers.x-pingback": {"$regex": "/xmlrpc\\.php$"}}
            ]
          },
          "extract_version": [
            {"body": "<meta[^>]+WordPress\\s+([\\d.]+)"}
          ]
        }
      ],
      "browser": [
        {
          "path": "/",
          "detection": "return typeof wp !== 'undefined';",
          "version": "try { return String(wp.version || ''); } catch(e){ return ''; }"
        }
      ]
    }
  }
}
```

## Detection Operators

### Logical Operators
- `$or` - Match ANY condition
- `$and` - Match ALL conditions
- `$not` - Negate condition
- `$nor` - Match NONE

### Comparison Operators
- `$regex` - Regular expression match (supports version extraction)
- `$eq` - Exact equality
- `$ne` - Not equal
- `$exists` - Field existence check
- `$in` - Value in array
- `$nin` - Value NOT in array

See [SCHEMA_GUIDE.md](SCHEMA_GUIDE.md) for detailed documentation.

## Advanced Features

### Smart Redirect Detection
- Follows same-domain redirects (max 3)
- Accumulates bodies and headers from all redirect steps
- Performs technology detection at each redirect

### Fatal Error Detection
- Stops immediately on fatal network errors (`no such host`, `network unreachable`)
- Avoids wasting time on unreachable domains

### Browser Detection
- Executes JavaScript to detect client-side technologies
- Extracts accurate version information
- Conditional execution based on HTTP detection results

## Performance

- **HTTP Detection**: < 2s for 10 paths
- **Browser Detection**: < 5s per page
- **Memory Usage**: < 100MB for 100 technologies

## Project Structure

```
.
├── cmd/
│   └── techdetect/
│       └── main.go              # CLI application
├── data/
│   ├── categories.json          # Technology categories
│   └── fingerprints/
│       └── *.json               # Organized fingerprint files
├── browser_detector.go          # Browser-based detection (Chromedp)
├── detector.go                  # Main detector orchestration
├── favicon.go                   # Favicon mmh3 and MD5 hash detection
├── http_detector.go             # HTTP-based detection
├── loader.go                    # Fingerprint loader
├── query.go                     # MongoDB-style query evaluator
├── types.go                     # Core data structures
├── go.mod
└── README.md
```

## Credits

This project is inspired by and uses fingerprint data converted from [ProjectDiscovery's wappalyzergo](https://github.com/projectdiscovery/wappalyzergo).

**Key Enhancements:**
- Reorganized fingerprints into categorized files for better maintainability
- Implemented MongoDB-style query evaluation for more accurate detection
- Added browser detection capabilities with JavaScript execution
- Enhanced redirect handling and error detection

## License

MIT
