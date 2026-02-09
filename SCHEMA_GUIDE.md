# Simplified Technology Detection Schema

## Overview

This document describes the simplified schema for technology detection fingerprints. The schema uses only **two detection fields**: `headers` and `body`, keeping the design clean and focused.

## Core Structure

```json
{
  "apps": {
    "Technology-Name": {
      "cats": [1, 6],
      "implies": ["PHP"],
      "paths": [...],
      "browser": [...],
      "description": "...",
      "website": "https://example.com",
      "icon": "icon.svg"
    }
  }
}
```

## Detection Fields

### 1. Headers Detection

Access HTTP response headers using dot notation:

```json
{
  "headers.server": { "$regex": "nginx" },
  "headers.x-powered-by": { "$regex": "PHP/([0-9.]+)\\;version:\\1" },
  "headers.set-cookie": { "$regex": "PHPSESSID" }
}
```

### 2. Body Detection

Match patterns in the HTML response body:

```json
{
  "body": { "$regex": "<link[^>]+/wp-content/" }
}
```

> **Note**: The `body` field contains the full HTTP response body (typically HTML).

## Supported Operators

### Logical Operators

#### `$or` - Match ANY condition
```json
{
  "$or": [
    { "body": { "$regex": "pattern1" } },
    { "body": { "$regex": "pattern2" } }
  ]
}
```

#### `$and` - Match ALL conditions
```json
{
  "$and": [
    { "headers.server": { "$regex": "nginx" } },
    { "body": { "$regex": "WordPress" } }
  ]
}
```

#### `$not` - Negate condition
```json
{
  "$not": {
    "headers.x-powered-by": { "$regex": "PHP" }
  }
}
```

#### `$nor` - Match NONE of the conditions
```json
{
  "$nor": [
    { "body": { "$regex": "Lodash" } },
    { "body": { "$regex": "Underscore" } }
  ]
}
```

### Comparison Operators

#### `$regex` - Regular expression match
```json
{
  "body": { "$regex": "/wp-content/themes/" }
}
```

**Version Extraction**: Use regex with capture groups and `;version:` syntax:
```json
{
  "headers.x-powered-by": { 
    "$regex": "^WordPress/([0-9.]+)\\;version:\\1" 
  }
}
```

#### `$eq` - Exact equality
```json
{
  "headers.server": { "$eq": "nginx" }
}
```

#### `$ne` - Not equal
```json
{
  "headers.x-frame-options": { "$ne": "DENY" }
}
```

#### `$exists` - Field existence check
```json
{
  "headers.x-powered-by": { "$exists": true }
}
```

#### `$in` - Value in array
```json
{
  "headers.server": { 
    "$in": ["nginx", "apache", "lighttpd"] 
  }
}
```

#### `$nin` - Value NOT in array
```json
{
  "headers.server": { 
    "$nin": ["IIS", "Microsoft-IIS"] 
  }
}
```

## Complete Example

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
              {
                "body": {
                  "$regex": "<link [^>]+/wp-(?:content|includes)/"
                }
              },
              {
                "headers.x-pingback": {
                  "$regex": "/xmlrpc\\.php$"
                }
              },
              {
                "body": {
                  "$regex": "<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\\s*([\\d.]+)?[\"']\\;version:\\1"
                }
              }
            ]
          },
          "extract_version": [
            {
              "body": "<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\\s*([\\d.]+)[\"']"
            },
            {
              "headers.x-powered-by": "WordPress/([0-9.]+)"
            }
          ]
        }
      ],
      "browser": [
        {
          "path": "/",
          "detection": "return typeof wp !== 'undefined';",
          "version": "try { return String(wp.version || ''); } catch(e){ return ''; }"
        }
      ],
      "description": "WordPress is a free and open-source CMS.",
      "website": "https://wordpress.org",
      "icon": "WordPress.svg"
    }
  }
}
```

## Version Extraction

The `extract_version` field contains an array of extraction rules. Each rule is an object with a field name as key and a regex pattern as value.

**Format**: `{ "field_name": "regex_pattern_with_capture_group" }`

**Special Syntax**: Use `\;version:\1` in detection regex to extract version directly:
```json
{
  "body": {
    "$regex": "WordPress ([0-9.]+)\\;version:\\1"
  }
}
```

Otherwise, use separate `extract_version` rules:
```json
{
  "extract_version": [
    { "body": "WordPress ([0-9.]+)" },
    { "headers.app-version": "v([0-9.]+)" }
  ]
}
```

## Browser Detection

Browser detection runs JavaScript in a headless browser:

```json
{
  "browser": [
    {
      "path": "/",
      "detection": "return typeof jQuery !== 'undefined';",
      "version": "try { return String(jQuery.fn.jquery || ''); } catch(e){ return ''; }"
    }
  ]
}
```

- `detection`: JavaScript code that returns boolean (true if detected)
- `version`: JavaScript code that returns version string or empty string

## Best Practices

### 1. Use Specific Patterns

❌ **Bad** (too generic):
```json
{ "body": { "$regex": "wordpress" } }
```

✅ **Good** (specific):
```json
{ "body": { "$regex": "/wp-content/themes/" } }
```

### 2. Combine Multiple Signals

Use `$or` for multiple weak signals:
```json
{
  "$or": [
    { "body": { "$regex": "/wp-content/" } },
    { "body": { "$regex": "/wp-includes/" } },
    { "headers.x-pingback": { "$exists": true } }
  ]
}
```

### 3. Avoid False Positives

Use `$and` with negative patterns:
```json
{
  "$and": [
    { "body": { "$regex": "Powered by WordPress" } },
    {
      "$not": {
        "body": { "$regex": "fake-wordpress|test-wordpress" }
      }
    }
  ]
}
```

### 4. Anchored Regex Patterns

Use anchors (`^`, `$`, `\b`) to avoid partial matches:
```json
{
  "headers.server": { 
    "$regex": "^nginx/([0-9.]+)$\\;version:\\1" 
  }
}
```

## Field Reference Summary

| Field | Description | Example |
|-------|-------------|---------|
| `body` | Full HTTP response body | `"body": {"$regex": "pattern"}` |
| `headers.*` | HTTP response headers (dot notation) | `"headers.server": {"$eq": "nginx"}` |

## Operator Reference Summary

| Category | Operator | Description |
|----------|----------|-------------|
| **Logical** | `$or` | Match any condition |
| | `$and` | Match all conditions |
| | `$not` | Negate condition |
| | `$nor` | Match none of conditions |
| **Comparison** | `$regex` | Regex pattern match |
| | `$eq` | Exact equality |
| | `$ne` | Not equal |
| | `$exists` | Field exists |
| | `$in` | Value in array |
| | `$nin` | Value not in array |
