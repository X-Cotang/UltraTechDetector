package techdetect

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxFaviconSize = 1 << 20 // 1 MiB
	maxFaviconURLs = 3
)

var (
	linkTagRegex  = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relAttrRegex  = regexp.MustCompile(`(?i)\brel\s*=\s*["']([^"']+)["']`)
	hrefAttrRegex = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
)

// ComputeFaviconHash returns the Shodan-compatible MurmurHash3 x86/32 of a
// favicon: standard base64 with a newline every 76 characters and a trailing
// newline, then signed mmh3 (seed 0).
func ComputeFaviconHash(data []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.Grow(len(encoded) + len(encoded)/76 + 1)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3x86_32([]byte(b.String()), 0))
}

// ComputeFaviconMD5 returns the hex MD5 of raw favicon bytes (OWASP/WhatWeb style).
func ComputeFaviconMD5(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// murmur3x86_32 is MurmurHash3 x86 32-bit (SMHasher), seed typically 0.
func murmur3x86_32(data []byte, seed uint32) uint32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
		r1        = 15
		r2        = 13
		m         = 5
		n  uint32 = 0xe6546b64
	)

	h := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, r1)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, r2)
		h = h*m + n
	}

	tail := data[nblocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, r1)
		k *= c2
		h ^= k
	}

	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

func looksLikeHTML(data []byte) bool {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return false
	}
	if len(trimmed) > 64 {
		trimmed = trimmed[:64]
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html")
}

func isFaviconRel(rel string) bool {
	for _, part := range strings.Fields(strings.ToLower(rel)) {
		if part == "icon" {
			return true
		}
	}
	return false
}

func extractFaviconURLs(html, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var urls []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref).String()
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		urls = append(urls, resolved)
	}

	for _, tag := range linkTagRegex.FindAllString(html, -1) {
		relMatch := relAttrRegex.FindStringSubmatch(tag)
		hrefMatch := hrefAttrRegex.FindStringSubmatch(tag)
		if len(relMatch) < 2 || len(hrefMatch) < 2 {
			continue
		}
		if isFaviconRel(relMatch[1]) {
			add(hrefMatch[1])
		}
	}
	return urls
}

func collectFaviconURLs(baseURL, homepageBody string) []string {
	seen := make(map[string]struct{})
	var urls []string
	add := func(u string) {
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}

	base := originURL(baseURL)
	add(base + "/favicon.ico")
	for _, u := range extractFaviconURLs(homepageBody, base+"/") {
		add(u)
		if len(urls) >= maxFaviconURLs {
			break
		}
	}
	if len(urls) > maxFaviconURLs {
		urls = urls[:maxFaviconURLs]
	}
	return urls
}

func (hd *HTTPDetector) faviconClient() *http.Client {
	return &http.Client{
		Timeout:   RequestTimeout,
		Transport: hd.client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (hd *HTTPDetector) fetchFavicon(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := hd.faviconClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	data, err := readAtMost(resp.Body, maxFaviconSize)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || looksLikeHTML(data) {
		return nil, nil
	}
	return data, nil
}

func readAtMost(r io.Reader, n int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, int64(n)))
}

func (hd *HTTPDetector) detectByFavicon(baseURL, homepageBody string, fingerprints map[string]Fingerprint, results map[string]*Technology) {
	mmh3ToTechs := make(map[int32][]string)
	md5ToTechs := make(map[string][]string)
	for techName, fp := range fingerprints {
		if len(fp.FaviconHashes) == 0 && len(fp.FaviconMD5) == 0 {
			continue
		}
		if _, already := results[techName]; already {
			continue
		}
		for _, h := range fp.FaviconHashes {
			mmh3ToTechs[h] = append(mmh3ToTechs[h], techName)
		}
		for _, h := range fp.FaviconMD5 {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			md5ToTechs[h] = append(md5ToTechs[h], techName)
		}
	}
	if len(mmh3ToTechs) == 0 && len(md5ToTechs) == 0 {
		return
	}

	for _, faviconURL := range collectFaviconURLs(baseURL, homepageBody) {
		data, err := hd.fetchFavicon(faviconURL)
		if err != nil || len(data) == 0 {
			continue
		}
		addMatches := func(techs []string) {
			for _, techName := range techs {
				if _, already := results[techName]; already {
					continue
				}
				results[techName] = &Technology{Name: techName}
			}
		}
		addMatches(mmh3ToTechs[ComputeFaviconHash(data)])
		addMatches(md5ToTechs[ComputeFaviconMD5(data)])
	}
}
