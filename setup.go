package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// Source definitions — derived from actual tool source analysis:
//   subfinder (46 sources) + amass (15 unique) + bbot (25 unique)
//   + theHarvester (6 unique) + github/gitlab code search
//
// Only sources that require API keys are listed here.
// Free no-key sources (crtsh, rapiddns, anubisdb etc.) run automatically.
// ─────────────────────────────────────────────────────────────────

type Source struct {
	Name      string   // key name in keys.yaml
	SignupURL string   // registration page
	ValidURL  string   // endpoint to test key (empty = format check only)
	AuthStyle string   // header | queryparam | basic | token
	AuthParam string   // header name or query param name
	Group     string   // free | token | paid
	UsedBy    []string // which tools use this source
}

var sources = []Source{

	// ══════════════════════════════════════════
	// FREE TIER — get these first
	// ══════════════════════════════════════════

	{
		Name:      "alienvault",
		SignupURL: "https://otx.alienvault.com/api",
		ValidURL:  "https://otx.alienvault.com/api/v1/user/me",
		AuthStyle: "header",
		AuthParam: "X-OTX-API-KEY",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "virustotal",
		SignupURL: "https://www.virustotal.com/gui/join-us",
		ValidURL:  "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
		AuthStyle: "header",
		AuthParam: "x-apikey",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "chaos",
		SignupURL: "https://cloud.projectdiscovery.io",
		ValidURL:  "https://dns.projectdiscovery.io/dns/example.com/subdomains",
		AuthStyle: "header",
		AuthParam: "Authorization",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "fullhunt",
		SignupURL: "https://fullhunt.io/user/register",
		ValidURL:  "https://fullhunt.io/api/v1/auth/me",
		AuthStyle: "header",
		AuthParam: "X-API-KEY",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "leakix",
		SignupURL: "https://leakix.net",
		ValidURL:  "https://leakix.net/api/subdomains/example.com",
		AuthStyle: "header",
		AuthParam: "api-key",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "netlas",
		SignupURL: "https://app.netlas.io/registration",
		ValidURL:  "https://app.netlas.io/api/domains/?q=example.com&source_type=include&start=0&fields=*",
		AuthStyle: "header",
		AuthParam: "X-API-Key",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "certspotter",
		SignupURL: "https://sslmate.com/signup",
		ValidURL:  "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names",
		AuthStyle: "header",
		AuthParam: "Authorization",
		Group:     "free",
		UsedBy:    []string{"subfinder"},
	},
	{
		Name:      "abuseipdb",
		SignupURL: "https://www.abuseipdb.com/register",
		ValidURL:  "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1",
		AuthStyle: "header",
		AuthParam: "Key",
		Group:     "free",
		UsedBy:    []string{"subfinder"},
	},
	{
		Name:      "hackertarget",
		SignupURL: "https://hackertarget.com/api",
		ValidURL:  "https://api.hackertarget.com/hostsearch/?q=example.com&apikey=",
		AuthStyle: "queryparam",
		AuthParam: "apikey",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "urlscan",
		SignupURL: "https://urlscan.io/user/signup",
		ValidURL:  "https://urlscan.io/user/quotas/",
		AuthStyle: "header",
		AuthParam: "API-Key",
		Group:     "free",
		UsedBy:    []string{"amass", "bbot"},
	},
	{
		Name:      "bevigil",
		SignupURL: "https://bevigil.com/osint-api",
		ValidURL:  "https://osint.bevigil.com/api/example.com/subdomains/",
		AuthStyle: "header",
		AuthParam: "X-Access-Token",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "c99",
		SignupURL: "https://api.c99.nl",
		ValidURL:  "",
		AuthStyle: "queryparam",
		AuthParam: "key",
		Group:     "free",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "hunterio",
		SignupURL: "https://hunter.io/users/sign_up",
		ValidURL:  "https://api.hunter.io/v2/account",
		AuthStyle: "queryparam",
		AuthParam: "api_key",
		Group:     "free",
		UsedBy:    []string{"amass", "bbot", "theHarvester"},
	},
	{
		Name:      "trickest",
		SignupURL: "https://trickest.com",
		ValidURL:  "",
		AuthStyle: "header",
		AuthParam: "Authorization",
		Group:     "free",
		UsedBy:    []string{"subfinder", "bbot"},
	},

	// ══════════════════════════════════════════
	// TOKEN-BASED — code search
	// ══════════════════════════════════════════

	{
		Name:      "github",
		SignupURL: "https://github.com/settings/tokens",
		ValidURL:  "https://api.github.com/user",
		AuthStyle: "token",
		AuthParam: "Authorization",
		Group:     "token",
		UsedBy:    []string{"subfinder", "amass", "github-subdomains"},
	},
	{
		Name:      "gitlab",
		SignupURL: "https://gitlab.com/-/profile/personal_access_tokens",
		ValidURL:  "https://gitlab.com/api/v4/user",
		AuthStyle: "header",
		AuthParam: "PRIVATE-TOKEN",
		Group:     "token",
		UsedBy:    []string{"subfinder", "amass", "gitlab-subdomains"},
	},

	// ══════════════════════════════════════════
	// PAID / LIMITED FREE
	// ══════════════════════════════════════════

	{
		Name:      "securitytrails",
		SignupURL: "https://securitytrails.com/app/signup",
		ValidURL:  "https://api.securitytrails.com/v1/ping",
		AuthStyle: "header",
		AuthParam: "APIKEY",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "bbot", "theHarvester"},
	},
	{
		Name:      "shodan",
		SignupURL: "https://account.shodan.io",
		ValidURL:  "https://api.shodan.io/api-info?key=",
		AuthStyle: "queryparam",
		AuthParam: "key",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "bbot", "theHarvester"},
	},
	{
		Name:      "censys_id",
		SignupURL: "https://search.censys.io/register",
		ValidURL:  "https://search.censys.io/api/v1/account",
		AuthStyle: "basic",
		AuthParam: "",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "censys_secret",
		SignupURL: "https://search.censys.io/register",
		ValidURL:  "",
		AuthStyle: "basic",
		AuthParam: "",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "intelx",
		SignupURL: "https://intelx.io/signup",
		ValidURL:  "https://2.intelx.io/authenticate/info",
		AuthStyle: "header",
		AuthParam: "x-key",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "theHarvester"},
	},
	{
		Name:      "fofa_email",
		SignupURL: "https://fofa.info",
		ValidURL:  "",
		AuthStyle: "queryparam",
		AuthParam: "email",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "fofa_key",
		SignupURL: "https://fofa.info",
		ValidURL:  "https://fofa.info/api/v1/info/my?email=&key=",
		AuthStyle: "queryparam",
		AuthParam: "key",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "zoomeyeapi",
		SignupURL: "https://www.zoomeye.org",
		ValidURL:  "https://api.zoomeye.org/user/info",
		AuthStyle: "header",
		AuthParam: "API-KEY",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "whoisxmlapi",
		SignupURL: "https://user.whoisxmlapi.com/sign-up",
		ValidURL:  "https://subdomains.whoisxmlapi.com/api/v1?apiKey=&domainName=example.com",
		AuthStyle: "queryparam",
		AuthParam: "apiKey",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "passivetotal",
		SignupURL: "https://community.riskiq.com/registration",
		ValidURL:  "https://api.riskiq.net/pt/v2/account",
		AuthStyle: "basic",
		AuthParam: "",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass", "bbot"},
	},
	{
		Name:      "dnsdb",
		SignupURL: "https://www.farsightsecurity.com/solutions/dnsdb",
		ValidURL:  "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/example.com",
		AuthStyle: "header",
		AuthParam: "X-API-Key",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "binaryedge",
		SignupURL: "https://app.binaryedge.io/sign-up",
		ValidURL:  "https://api.binaryedge.io/v2/user/subscription",
		AuthStyle: "header",
		AuthParam: "X-Key",
		Group:     "paid",
		UsedBy:    []string{"subfinder", "amass"},
	},
	{
		Name:      "quake",
		SignupURL: "https://quake.360.net/quake/#/index",
		ValidURL:  "https://quake.360.net/api/v3/user/info",
		AuthStyle: "header",
		AuthParam: "X-QuakeToken",
		Group:     "paid",
		UsedBy:    []string{"subfinder"},
	},
	{
		Name:      "redhuntlabs",
		SignupURL: "https://redhuntlabs.com/api",
		ValidURL:  "",
		AuthStyle: "header",
		AuthParam: "X-BLOBR-KEY",
		Group:     "paid",
		UsedBy:    []string{"subfinder"},
	},
	{
		Name:      "merklemap",
		SignupURL: "https://www.merklemap.com",
		ValidURL:  "",
		AuthStyle: "header",
		AuthParam: "Authorization",
		Group:     "paid",
		UsedBy:    []string{"subfinder"},
	},
	{
		Name:      "dehashed",
		SignupURL: "https://www.dehashed.com/register",
		ValidURL:  "https://api.dehashed.com/search?query=example.com&size=1",
		AuthStyle: "basic",
		AuthParam: "",
		Group:     "paid",
		UsedBy:    []string{"bbot"},
	},
	{
		Name:      "huntermap",
		SignupURL: "https://hunter.how",
		ValidURL:  "",
		AuthStyle: "queryparam",
		AuthParam: "api-key",
		Group:     "paid",
		UsedBy:    []string{"subfinder"},
	},
}

// ─────────────────────────────────────────────
// Terminal helpers
// ─────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	white  = "\033[97m"
	gray   = "\033[37m"
	dkgray = "\033[90m"
)

func tagLine(t, color, msg string) {
	fmt.Printf("  %s%-3s%s  %s\n", color, t, reset, msg)
}
func inf(msg string)  { tagLine("inf", dkgray, gray+msg+reset) }
func ok_(msg string)  { tagLine("ok", gray, white+msg+reset) }
func wrn(msg string)  { tagLine("wrn", gray, gray+msg+reset) }
func err_(msg string) { tagLine("!!!", white, white+bold+msg+reset) }

func divider() {
	fmt.Println(dkgray + "  " + strings.Repeat("─", 58) + reset)
}

func sectionHdr(title string) {
	fmt.Printf("\n%s  %s%s\n", dkgray, strings.ToUpper(title), reset)
}

func printBanner() {
	fmt.Println()
	fmt.Println(dkgray + `     _ _   _  _  _ _` + reset)
	fmt.Println(dkgray + `    | | | | || || | |` + reset)
	fmt.Println(dkgray + ` _  | | |_| || || | |` + reset)
	fmt.Println(dkgray + `| |_| |  _  || || | |` + reset)
	fmt.Println(dkgray + ` \___/|_| |_||_||_|_|` + reset)
	fmt.Println()
	fmt.Println(dkgray + "  reconnaissance orchestrator  v1.0.0" + reset)
	fmt.Println()
}

// ─────────────────────────────────────────────
// Config paths
// ─────────────────────────────────────────────

func juubiConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "juubi")
}
func juubiKeysPath() string { return filepath.Join(juubiConfigDir(), "keys.yaml") }
func subfinderConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "subfinder", "provider-config.yaml")
}
func amassConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "amass", "datasources.yaml")
}
func bbotConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "bbot", "secrets.yaml")
}

// ─────────────────────────────────────────────
// Probe signup URL — is the site reachable?
// ─────────────────────────────────────────────

type probeResult struct {
	name   string
	active bool
}

func probeURL(url string) bool {
	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow redirects
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}

func probeAllSignupURLs() map[string]bool {
	results := map[string]bool{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}

	// deduplicate URLs
	seen := map[string]bool{}
	urlToNames := map[string][]string{}
	for _, s := range sources {
		if s.SignupURL == "" || seen[s.SignupURL] {
			urlToNames[s.SignupURL] = append(urlToNames[s.SignupURL], s.Name)
			continue
		}
		seen[s.SignupURL] = true
		urlToNames[s.SignupURL] = append(urlToNames[s.SignupURL], s.Name)
	}

	for url := range seen {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			active := probeURL(u)
			mu.Lock()
			for _, name := range urlToNames[u] {
				results[name] = active
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()
	return results
}

// ─────────────────────────────────────────────
// keys.yaml template
// ─────────────────────────────────────────────

func keysYAMLTemplate(probeResults map[string]bool) string {
	var sb strings.Builder
	sb.WriteString("# ──────────────────────────────────────────────────────────\n")
	sb.WriteString("# Juubi — API Keys Configuration\n")
	sb.WriteString("# Fill values below. Leave as null to skip that source.\n")
	sb.WriteString("# Run 'juubi --setup' again after adding new keys.\n")
	sb.WriteString("# ──────────────────────────────────────────────────────────\n\n")

	groups := []string{"free", "token", "paid"}
	groupLabels := map[string]string{
		"free":  "FREE — all have free tiers, get these first",
		"token": "TOKEN-BASED — requires account",
		"paid":  "PAID / LIMITED FREE",
	}

	for _, g := range groups {
		sb.WriteString("# ── " + groupLabels[g] + "\n")
		seenURL := map[string]bool{}
		for _, s := range sources {
			if s.Group != g {
				continue
			}
			// write signup URL once per unique URL
			if s.SignupURL != "" && !seenURL[s.SignupURL] {
				active, probed := probeResults[s.Name]
				status := ""
				if probed {
					if active {
						status = "  # ✓ reachable"
					} else {
						status = "  # ✗ unreachable at time of setup"
					}
				}
				sb.WriteString(fmt.Sprintf("# signup: %s%s\n", s.SignupURL, status))
				seenURL[s.SignupURL] = true
			}
			sb.WriteString(fmt.Sprintf("# used by: %s\n", strings.Join(s.UsedBy, ", ")))
			sb.WriteString(fmt.Sprintf("%-22s null\n\n", s.Name+":"))
		}
	}
	return sb.String()
}

// ─────────────────────────────────────────────
// Read keys.yaml
// ─────────────────────────────────────────────

func readKeys(path string) map[string]string {
	keys := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return keys
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if v == "" || v == "null" {
			continue
		}
		v = strings.Trim(v, `"'`)
		keys[k] = v
	}
	return keys
}

// ─────────────────────────────────────────────
// Key validation — live API test
// ─────────────────────────────────────────────

func testKey(s Source, value string, censysSecret string) (bool, string) {
	if s.ValidURL == "" {
		return true, "no live test available — accepted"
	}

	client := &http.Client{Timeout: 8 * time.Second}
	url := s.ValidURL

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "invalid url"
	}

	switch s.AuthStyle {
	case "header":
		if s.Name == "github" {
			req.Header.Set("Authorization", "token "+value)
		} else if s.Name == "chaos" {
			req.Header.Set("Authorization", value)
		} else if s.Name == "certspotter" {
			req.Header.Set("Authorization", "Bearer "+value)
		} else {
			req.Header.Set(s.AuthParam, value)
		}
	case "token":
		req.Header.Set("Authorization", "token "+value)
	case "queryparam":
		q := req.URL.Query()
		q.Set(s.AuthParam, value)
		req.URL.RawQuery = q.Encode()
	case "basic":
		// censys uses id:secret basic auth
		req.SetBasicAuth(value, censysSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "request failed — check network"
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200, 201, 204:
		return true, "valid"
	case 401, 403:
		return false, fmt.Sprintf("rejected (HTTP %d)", resp.StatusCode)
	case 429:
		return true, "rate limited — likely valid"
	case 404:
		return false, fmt.Sprintf("endpoint not found (HTTP %d)", resp.StatusCode)
	default:
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}

// ─────────────────────────────────────────────
// Confirm overwrite
// ─────────────────────────────────────────────

func confirmOverwrite(path string) bool {
	fmt.Printf(dkgray+"  wrn  "+reset+gray+"  %s exists. overwrite? [y/N] "+reset, path)
	reader := bufio.NewReader(os.Stdin)
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	return ans == "y" || ans == "yes"
}

// ─────────────────────────────────────────────
// Open editor
// ─────────────────────────────────────────────

func openInEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		for _, e := range []string{"nano", "vim", "vi"} {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}
	if editor == "" {
		return fmt.Errorf("no editor found — set $EDITOR or install nano/vim")
	}
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ─────────────────────────────────────────────
// Inject into tool configs
// ─────────────────────────────────────────────

func injectSubfinder(keys map[string]string) error {
	path := subfinderConfigPath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if _, err := os.Stat(path); err == nil {
		if !confirmOverwrite(path) {
			return nil
		}
	}

	// subfinder provider-config format: source:\n  - key
	mapping := map[string]string{
		"alienvault":     "alienvault",
		"virustotal":     "virustotal",
		"securitytrails": "securitytrails",
		"shodan":         "shodan",
		"chaos":          "chaos",
		"github":         "github",
		"gitlab":         "gitlab",
		"fullhunt":       "fullhunt",
		"netlas":         "netlas",
		"leakix":         "leakix",
		"certspotter":    "certspotter",
		"abuseipdb":      "abuseipdb",
		"binaryedge":     "binaryedge",
		"intelx":         "intelx",
		"bevigil":        "bevigil",
		"c99":            "c99",
		"zoomeyeapi":     "zoomeye",
		"whoisxmlapi":    "whoisxmlapi",
		"passivetotal":   "passivetotal",
		"dnsdb":          "dnsdb",
		"quake":          "quake",
		"redhuntlabs":    "redhuntlabs",
		"merklemap":      "merklemap",
		"huntermap":      "hunter",
		"hackertarget":   "hackertarget",
		"trickest":       "trickest",
		"hunterio":       "hunter",
	}

	var sb strings.Builder
	sb.WriteString("# Generated by juubi --setup\n")
	written := map[string]bool{}
	for juubiKey, sfKey := range mapping {
		val, ok := keys[juubiKey]
		if !ok || written[sfKey] {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s:\n  - %s\n", sfKey, val))
		written[sfKey] = true
	}
	// censys needs id:secret
	if id, ok1 := keys["censys_id"]; ok1 {
		if secret, ok2 := keys["censys_secret"]; ok2 {
			sb.WriteString(fmt.Sprintf("censys:\n  - %s:%s\n", id, secret))
		}
	}
	// fofa needs email:key
	if email, ok1 := keys["fofa_email"]; ok1 {
		if key, ok2 := keys["fofa_key"]; ok2 {
			sb.WriteString(fmt.Sprintf("fofa:\n  - %s:%s\n", email, key))
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0600)
}

func injectAmass(keys map[string]string) error {
	path := amassConfigPath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if _, err := os.Stat(path); err == nil {
		if !confirmOverwrite(path) {
			return nil
		}
	}

	mapping := map[string]string{
		"alienvault":     "AlienVault",
		"virustotal":     "VirusTotal",
		"securitytrails": "SecurityTrails",
		"shodan":         "Shodan",
		"chaos":          "Chaos",
		"github":         "GitHub",
		"gitlab":         "GitLab",
		"fullhunt":       "FullHunt",
		"netlas":         "Netlas",
		"leakix":         "LeakIX",
		"binaryedge":     "BinaryEdge",
		"intelx":         "IntelX",
		"bevigil":        "BeVigil",
		"c99":            "C99",
		"hunterio":       "Hunter",
		"zoomeyeapi":     "ZoomEye",
		"whoisxmlapi":    "WhoisXMLAPI",
		"passivetotal":   "PassiveTotal",
		"dnsdb":          "DNSDB",
		"hackertarget":   "HackerTarget",
		"urlscan":        "URLScan",
		"trickest":       "Trickest",
	}

	var sb strings.Builder
	sb.WriteString("# Generated by juubi --setup\n")
	sb.WriteString("global_options:\n  minimum_ttl: 1440\n\ndatasources:\n")

	for juubiKey, amassName := range mapping {
		val, ok := keys[juubiKey]
		if !ok {
			continue
		}
		sb.WriteString(fmt.Sprintf("  - name: %s\n    creds:\n      account:\n        apikey: %s\n", amassName, val))
	}
	if id, ok1 := keys["censys_id"]; ok1 {
		if secret, ok2 := keys["censys_secret"]; ok2 {
			sb.WriteString(fmt.Sprintf("  - name: Censys\n    creds:\n      account:\n        username: %s\n        apikey: %s\n", id, secret))
		}
	}
	if email, ok1 := keys["fofa_email"]; ok1 {
		if key, ok2 := keys["fofa_key"]; ok2 {
			sb.WriteString(fmt.Sprintf("  - name: FOFA\n    creds:\n      account:\n        username: %s\n        apikey: %s\n", email, key))
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0600)
}

func injectBbot(keys map[string]string) error {
	path := bbotConfigPath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if _, err := os.Stat(path); err == nil {
		if !confirmOverwrite(path) {
			return nil
		}
	}

	// bbot secrets.yaml format: service:\n  key: value
	entries := map[string][2]string{
		"virustotal":     {"virustotal", "api_key"},
		"securitytrails": {"securitytrails", "api_key"},
		"shodan":         {"shodan", "api_key"},
		"chaos":          {"chaos", "api_key"},
		"github":         {"github", "api_key"},
		"fullhunt":       {"fullhunt", "api_key"},
		"leakix":         {"leakix", "api_key"},
		"bevigil":        {"bevigil", "api_key"},
		"c99":            {"c99", "api_key"},
		"hackertarget":   {"hackertarget", "api_key"},
		"urlscan":        {"urlscan", "api_key"},
		"hunterio":       {"hunter", "api_key"},
		"trickest":       {"trickest", "api_key"},
		"dehashed":       {"dehashed", "api_key"},
		"censys_id":      {"censys", "api_id"},
		"censys_secret":  {"censys", "api_secret"},
	}

	type bbotEntry struct {
		service string
		field   string
		value   string
	}
	collected := map[string][]bbotEntry{}
	for juubiKey, parts := range entries {
		val, ok := keys[juubiKey]
		if !ok {
			continue
		}
		collected[parts[0]] = append(collected[parts[0]], bbotEntry{parts[0], parts[1], val})
	}

	var sb strings.Builder
	sb.WriteString("# Generated by juubi --setup\n")
	for service, fields := range collected {
		sb.WriteString(service + ":\n")
		for _, f := range fields {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", f.field, f.value))
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0600)
}

// ─────────────────────────────────────────────
// Setup entrypoint
// ─────────────────────────────────────────────

func runSetup() {
	printBanner()
	divider()
	inf("starting setup")
	inf("config  " + white + juubiKeysPath() + reset)
	inf("keys written to tool configs once — never touched during scan")
	divider()

	// ── Step 1: probe signup URLs ─────────────
	sectionHdr("probing signup urls")
	fmt.Printf(gray + "  checking reachability of " + white +
		fmt.Sprintf("%d", len(sources)) + gray + " sources..." + reset + "\n")

	probeResults := probeAllSignupURLs()

	unreachable := []string{}
	for _, s := range sources {
		active, ok := probeResults[s.Name]
		if ok && !active {
			unreachable = append(unreachable, s.Name)
		}
	}
	if len(unreachable) > 0 {
		wrn(fmt.Sprintf("%d signup URLs unreachable right now:", len(unreachable)))
		for _, name := range unreachable {
			for _, s := range sources {
				if s.Name == name {
					fmt.Printf("  %s%-20s%s %s%s%s\n", dkgray, name, reset, dim, s.SignupURL, reset)
					break
				}
			}
		}
	} else {
		ok_("all signup URLs reachable")
	}

	// ── Step 2: create config dir ─────────────
	if err := os.MkdirAll(juubiConfigDir(), 0755); err != nil {
		err_("failed to create config dir: " + err.Error())
		os.Exit(1)
	}

	// ── Step 3: write template ────────────────
	keysPath := juubiKeysPath()
	if _, statErr := os.Stat(keysPath); os.IsNotExist(statErr) {
		content := keysYAMLTemplate(probeResults)
		if err := os.WriteFile(keysPath, []byte(content), 0600); err != nil {
			err_("failed to write keys.yaml: " + err.Error())
			os.Exit(1)
		}
		ok_("created " + keysPath)
	} else {
		wrn("keys.yaml exists — opening for editing")
	}

	// ── Step 4: show missing key URLs ─────────
	existing := readKeys(keysPath)
	sectionHdr("sources without keys")
	missingCount := 0
	groups := []string{"free", "token", "paid"}
	for _, g := range groups {
		shownGroup := false
		for _, s := range sources {
			if s.Group != g {
				continue
			}
			if _, ok := existing[s.Name]; ok {
				continue
			}
			if !shownGroup {
				fmt.Printf("\n%s  %s%s\n", dkgray, strings.ToUpper(g), reset)
				shownGroup = true
			}
			active := probeResults[s.Name]
			reach := dkgray + "✗" + reset
			if active {
				reach = gray + "✓" + reset
			}
			fmt.Printf("  %s  %s%-22s%s %s%s%s\n",
				reach, gray, s.Name, reset, dim, s.SignupURL, reset)
			missingCount++
		}
	}
	if missingCount == 0 {
		ok_("all keys already configured")
	}

	// ── Step 5: open editor ───────────────────
	fmt.Println()
	inf("opening " + white + keysPath + reset)
	fmt.Println()
	if err := openInEditor(keysPath); err != nil {
		err_("could not open editor: " + err.Error())
		err_("manually edit: " + keysPath)
		err_("then re-run: juubi --setup")
		os.Exit(1)
	}

	// ── Step 6: read updated keys ─────────────
	keys := readKeys(keysPath)
	if len(keys) == 0 {
		wrn("no keys found — all sources will run unauthenticated")
		wrn("run 'juubi --setup' again after adding keys")
		return
	}

	// ── Step 7: validate keys live ────────────
	sectionHdr("validating keys")
	validKeys := map[string]string{}
	invalidCount := 0
	censysSecret, _ := keys["censys_secret"]

	for _, s := range sources {
		val, ok := keys[s.Name]
		if !ok {
			continue
		}
		fmt.Printf(gray+"  testing  %-22s"+reset, s.Name)
		valid, msg := testKey(s, val, censysSecret)
		if valid {
			fmt.Printf(gray+"%s\n"+reset, msg)
			validKeys[s.Name] = val
		} else {
			fmt.Printf(white+"FAIL — %s\n"+reset, msg)
			invalidCount++
		}
	}

	if invalidCount > 0 {
		fmt.Println()
		wrn(fmt.Sprintf("%d key(s) failed — fix in %s and re-run setup", invalidCount, keysPath))
	}

	// ── Step 8: inject into tool configs ──────
	sectionHdr("writing tool configs")
	type inj struct {
		name string
		path string
		fn   func(map[string]string) error
	}
	injections := []inj{
		{"subfinder", subfinderConfigPath(), injectSubfinder},
		{"amass    ", amassConfigPath(), injectAmass},
		{"bbot     ", bbotConfigPath(), injectBbot},
	}
	for _, i := range injections {
		if err := i.fn(validKeys); err != nil {
			err_("failed " + strings.TrimSpace(i.name) + ": " + err.Error())
		} else {
			ok_("wrote  " + i.path)
		}
	}

	// ── Step 9: summary ───────────────────────
	divider()
	total := len(sources)
	active := len(validKeys)
	skipped := total - active
	ok_(fmt.Sprintf("%d / %d sources active", active, total))
	if skipped > 0 {
		wrn(fmt.Sprintf("%d sources skipped — warnings shown during scan", skipped))
	}
	fmt.Println()
	inf("done. run " + white + "juubi -t <target>" + reset + gray + " to start")

	if runtime.GOOS == "windows" {
		fmt.Println()
		wrn("windows detected — some tools may behave differently")
	}
	fmt.Println()
}
