package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────

// ToolDef mirrors tools.yaml structure
type ToolDef struct {
	Name         string `yaml:"name"`
	Category     string `yaml:"category"`
	Binary       string `yaml:"binary"`
	Flags        string `yaml:"flags"`
	OutputFormat string `yaml:"output_format"`
	Enabled      bool   `yaml:"enabled"`
}

type ToolsConfig struct {
	Settings struct {
		OutputDir string `yaml:"output_dir"`
		Timeout   int    `yaml:"timeout"`
		Threads   int    `yaml:"threads"`
		Resolvers string `yaml:"resolvers"`
		Wordlist  string `yaml:"wordlist"`
	} `yaml:"settings"`
	Tools []ToolDef `yaml:"tools"`
}

// Result from a single tool
type ToolResult struct {
	Tool       string
	Subdomains []string
	Err        error
	Duration   time.Duration
	Skipped    bool
	SkipReason string
}

// Enriched subdomain entry
type SubdomainEntry struct {
	Subdomain string
	IPs       []string
	Sources   []string
	Resolved  bool
}

// ─────────────────────────────────────────────────────────────────
// Load tools.yaml
// ─────────────────────────────────────────────────────────────────

func loadToolsConfig(path string) (*ToolsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read tools.yaml: %w", err)
	}
	var cfg ToolsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse tools.yaml: %w", err)
	}
	return &cfg, nil
}

// ─────────────────────────────────────────────────────────────────
// Token injection — reads keys.yaml, returns env + flag map
// ─────────────────────────────────────────────────────────────────

type KeysRuntime struct {
	GithubToken string
	GitlabToken string
	EnvVars     []string // KEY=VALUE pairs for subprocess env
}

func loadKeysRuntime() *KeysRuntime {
	home, _ := os.UserHomeDir()
	keysPath := filepath.Join(home, ".config", "juubi", "keys.yaml")
	keys := readKeys(keysPath) // reuse from setup.go

	kr := &KeysRuntime{}

	// env var mapping for subfinder
	envMap := map[string]string{
		"alienvault":     "ALIENVAULT_API_KEY",
		"virustotal":     "VIRUSTOTAL_API_KEY",
		"securitytrails": "SECURITYTRAILS_API_KEY",
		"shodan":         "SHODAN_API_KEY",
		"chaos":          "PDCP_API_KEY",
		"fullhunt":       "FULLHUNT_API_KEY",
		"leakix":         "LEAKIX_API_KEY",
		"netlas":         "NETLAS_API_KEY",
		"certspotter":    "CERTSPOTTER_API_KEY",
		"abuseipdb":      "ABUSEIPDB_API_KEY",
		"binaryedge":     "BINARYEDGE_API_KEY",
		"bevigil":        "BEVIGIL_API_KEY",
		"c99":            "C99_API_KEY",
		"intelx":         "INTELX_KEY",
		"zoomeyeapi":     "ZOOMEYE_API_KEY",
		"whoisxmlapi":    "WHOISXML_API_KEY",
		"passivetotal":   "PASSIVETOTAL_KEY",
		"dnsdb":          "DNSDB_API_KEY",
		"quake":          "QUAKE_TOKEN",
		"redhuntlabs":    "REDHUNTLABS_KEY",
		"merklemap":      "MERKLEMAP_KEY",
		"huntermap":      "HUNTER_API_KEY",
		"hackertarget":   "HACKERTARGET_API_KEY",
		"trickest":       "TRICKEST_KEY",
		"hunterio":       "HUNTER_API_KEY",
		"urlscan":        "URLSCAN_API_KEY",
		"dehashed":       "DEHASHED_API_KEY",
		"fofa_email":     "FOFA_EMAIL",
		"fofa_key":       "FOFA_KEY",
		"censys_id":      "CENSYS_API_ID",
		"censys_secret":  "CENSYS_API_SECRET",
	}

	// start with current env
	kr.EnvVars = os.Environ()

	for juubiKey, envKey := range envMap {
		if val, ok := keys[juubiKey]; ok {
			kr.EnvVars = append(kr.EnvVars, envKey+"="+val)
		}
	}

	if t, ok := keys["github"]; ok {
		kr.GithubToken = t
		kr.EnvVars = append(kr.EnvVars, "GITHUB_TOKEN="+t)
	}
	if t, ok := keys["gitlab"]; ok {
		kr.GitlabToken = t
		kr.EnvVars = append(kr.EnvVars, "GITLAB_TOKEN="+t)
	}

	return kr
}

// ─────────────────────────────────────────────────────────────────
// Build command for each tool
// ─────────────────────────────────────────────────────────────────

func buildCommand(tool ToolDef, target string, cfg *ToolsConfig, kr *KeysRuntime) ([]string, error) {
	flags := tool.Flags
	flags = strings.ReplaceAll(flags, "{target}", target)
	flags = strings.ReplaceAll(flags, "{wordlist}", cfg.Settings.Wordlist)
	flags = strings.ReplaceAll(flags, "{resolvers}", cfg.Settings.Resolvers)
	flags = strings.ReplaceAll(flags, fmt.Sprintf("%d", 0), fmt.Sprintf("%d", cfg.Settings.Threads))

	// inject tokens for tools that need them as flags
	switch tool.Name {
	case "github-subdomains":
		if kr.GithubToken == "" {
			return nil, fmt.Errorf("GITHUB_TOKEN not set")
		}
		flags = strings.ReplaceAll(flags, "{github_token}", kr.GithubToken)
	case "gitlab-subdomains":
		if kr.GitlabToken == "" {
			return nil, fmt.Errorf("GITLAB_TOKEN not set")
		}
		flags = strings.ReplaceAll(flags, "{gitlab_token}", kr.GitlabToken)
	case "theHarvester":
		// inject securitytrails key if available for theHarvester
		for _, env := range kr.EnvVars {
			if strings.HasPrefix(env, "SECURITYTRAILS_API_KEY=") {
				val := strings.TrimPrefix(env, "SECURITYTRAILS_API_KEY=")
				flags += " -key " + val
				break
			}
		}
	}

	parts := []string{tool.Binary}
	parts = append(parts, strings.Fields(flags)...)
	return parts, nil
}

// ─────────────────────────────────────────────────────────────────
// Parse tool output — extract subdomain lines
// ─────────────────────────────────────────────────────────────────

func parseOutput(output string, tool ToolDef, target string) []string {
	seen := map[string]bool{}
	var results []string

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// skip log/info lines
		if strings.HasPrefix(line, "[") ||
			strings.HasPrefix(line, "#") ||
			strings.Contains(line, "ERROR") ||
			strings.Contains(line, "error") ||
			strings.Contains(line, "Warning") {
			continue
		}

		var sub string

		switch tool.OutputFormat {
		case "json":
			// try to extract from JSON
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
				for _, k := range []string{"host", "subdomain", "name", "domain"} {
					if v, ok := obj[k].(string); ok {
						sub = v
						break
					}
				}
			}
		default:
			// text — take the first field (handle csv and space-separated)
			fields := strings.FieldsFunc(line, func(r rune) bool {
				return r == ',' || r == '\t' || r == ' '
			})
			if len(fields) > 0 {
				sub = fields[0]
			}
		}

		sub = strings.ToLower(strings.TrimSpace(sub))
		sub = strings.TrimPrefix(sub, "www.")

		// validate it actually belongs to target
		if sub == "" || !strings.HasSuffix(sub, "."+target) && sub != target {
			continue
		}

		// basic FQDN sanity check
		if strings.Contains(sub, " ") || strings.Contains(sub, "/") {
			continue
		}

		if !seen[sub] {
			seen[sub] = true
			results = append(results, sub)
		}
	}
	return results
}

// ─────────────────────────────────────────────────────────────────
// Run a single tool
// ─────────────────────────────────────────────────────────────────

func runTool(tool ToolDef, target string, cfg *ToolsConfig, kr *KeysRuntime) ToolResult {
	start := time.Now()
	result := ToolResult{Tool: tool.Name}

	// check binary exists
	if _, err := exec.LookPath(tool.Binary); err != nil {
		result.Skipped = true
		result.SkipReason = fmt.Sprintf("binary '%s' not found in PATH", tool.Binary)
		result.Duration = time.Since(start)
		return result
	}

	// build command
	cmdParts, err := buildCommand(tool, target, cfg, kr)
	if err != nil {
		result.Skipped = true
		result.SkipReason = err.Error()
		result.Duration = time.Since(start)
		return result
	}

	// run with timeout
	timeout := time.Duration(cfg.Settings.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
	cmd.Env = kr.EnvVars

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			// timeout — use whatever output we got
			result.Subdomains = parseOutput(stdout.String(), tool, target)
			result.Err = fmt.Errorf("timed out after %s", timeout)
			result.Duration = time.Since(start)
			return result
		}
		// non-zero exit — still try to parse stdout
		result.Subdomains = parseOutput(stdout.String(), tool, target)
		result.Err = fmt.Errorf("exited with error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = parseOutput(stdout.String(), tool, target)
	result.Duration = time.Since(start)
	return result
}

// ─────────────────────────────────────────────────────────────────
// DNS resolution — resolve IPs for a subdomain
// ─────────────────────────────────────────────────────────────────

func resolveSubdomain(sub string) ([]string, bool) {
	resolver := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, sub)
	if err != nil || len(addrs) == 0 {
		return nil, false
	}
	return addrs, true
}

func resolveAll(subdomains []string) map[string][]string {
	results := map[string][]string{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, 50) // 50 concurrent resolvers

	for _, sub := range subdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ips, ok := resolveSubdomain(s)
			mu.Lock()
			if ok {
				results[s] = ips
			} else {
				results[s] = nil // mark as unresolved
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return results
}

// ─────────────────────────────────────────────────────────────────
// Merge all tool results
// ─────────────────────────────────────────────────────────────────

func mergeResults(toolResults []ToolResult) map[string][]string {
	// subdomain -> list of tools that found it
	merged := map[string][]string{}
	for _, tr := range toolResults {
		for _, sub := range tr.Subdomains {
			merged[sub] = append(merged[sub], tr.Tool)
		}
	}
	return merged
}

// ─────────────────────────────────────────────────────────────────
// Write output files
// ─────────────────────────────────────────────────────────────────

func writeOutputs(target string, outputDir string, entries []SubdomainEntry) error {
	dir := filepath.Join(outputDir, target)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create output dir: %w", err)
	}

	// ── subdomains.txt — clean list ───────────
	subFile := filepath.Join(dir, "subdomains.txt")
	sf, err := os.Create(subFile)
	if err != nil {
		return err
	}
	defer sf.Close()
	for _, e := range entries {
		fmt.Fprintln(sf, e.Subdomain)
	}

	// ── verbose.csv — subdomain,ip,source ─────
	csvFile := filepath.Join(dir, "verbose.csv")
	cf, err := os.Create(csvFile)
	if err != nil {
		return err
	}
	defer cf.Close()
	fmt.Fprintln(cf, "subdomain,ip,sources,resolved")
	for _, e := range entries {
		ips := strings.Join(e.IPs, ";")
		srcs := strings.Join(e.Sources, ";")
		resolved := "true"
		if !e.Resolved {
			resolved = "false"
		}
		fmt.Fprintf(cf, "%s,%s,%s,%s\n", e.Subdomain, ips, srcs, resolved)
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────
// Print live result row
// ─────────────────────────────────────────────────────────────────

var (
	printMu  sync.Mutex
	rowCount int
)

func printResultRow(entry SubdomainEntry) {
	printMu.Lock()
	defer printMu.Unlock()
	rowCount++

	ip := "—"
	if len(entry.IPs) > 0 {
		ip = entry.IPs[0]
	}
	src := "—"
	if len(entry.Sources) > 0 {
		src = strings.Join(entry.Sources, ",")
	}

	fmt.Printf("  %s%03d%s  %-45s  %-18s  %s%s%s\n",
		dkgray, rowCount, reset,
		gray+entry.Subdomain+reset,
		dkgray+ip+reset,
		dim, src, reset,
	)
}

// ─────────────────────────────────────────────────────────────────
// Print tool status line
// ─────────────────────────────────────────────────────────────────

func printToolDone(tr ToolResult) {
	printMu.Lock()
	defer printMu.Unlock()

	dur := tr.Duration.Round(time.Millisecond).String()

	if tr.Skipped {
		fmt.Printf("  %swrn%s  %-20s skipped — %s\n",
			gray, reset, tr.Tool, tr.SkipReason)
		return
	}
	if tr.Err != nil {
		fmt.Printf("  %s!!!%s  %-20s %serror%s — %s  %s(%d results)%s\n",
			white, reset, tr.Tool, white, reset,
			tr.Err.Error(), dkgray, len(tr.Subdomains), reset)
		return
	}
	fmt.Printf("  %s ok%s  %-20s %s+%d%s  %s%s%s\n",
		gray, reset,
		tr.Tool,
		white, len(tr.Subdomains), reset,
		dkgray, dur, reset,
	)
}

// ─────────────────────────────────────────────────────────────────
// Enumeration entrypoint
// ─────────────────────────────────────────────────────────────────

func runEnum(target string, toolsConfigPath string) {
	start := time.Now()

	printBanner()
	divider()
	inf("target   " + white + target + reset)
	inf("mode     " + gray + "passive" + reset)

	// ── Load tools config ─────────────────────
	cfg, err := loadToolsConfig(toolsConfigPath)
	if err != nil {
		err_("could not load tools.yaml: " + err.Error())
		os.Exit(1)
	}

	// ── Load keys ────────────────────────────
	kr := loadKeysRuntime()

	// count active keys
	keyCount := 0
	for _, env := range kr.EnvVars {
		for _, s := range sources {
			if strings.HasPrefix(env, strings.ToUpper(s.Name)+"=") ||
				strings.HasPrefix(env, "PDCP_API_KEY=") ||
				strings.HasPrefix(env, "GITHUB_TOKEN=") {
				keyCount++
				break
			}
		}
	}

	// warn about missing keys
	home, _ := os.UserHomeDir()
	keysPath := filepath.Join(home, ".config", "juubi", "keys.yaml")
	existingKeys := readKeys(keysPath)
	missingCount := 0
	for _, s := range sources {
		if _, ok := existingKeys[s.Name]; !ok {
			fmt.Printf("  %swrn%s  %s not set %s— skipping source%s\n",
				gray, reset, s.Name, dkgray, reset)
			missingCount++
		}
	}
	if missingCount > 0 {
		fmt.Println()
		wrn(fmt.Sprintf("%d sources inactive — run 'juubi --setup' to add keys", missingCount))
	}

	inf(fmt.Sprintf("output   %s./output/%s/%s", white, target, reset))

	// filter enabled tools
	var enabledTools []ToolDef
	for _, t := range cfg.Tools {
		if t.Enabled {
			enabledTools = append(enabledTools, t)
		}
	}
	inf(fmt.Sprintf("tools    %s%d enabled%s", white, len(enabledTools), reset))
	divider()

	// ── Run all tools in parallel ─────────────
	sectionHdr("running tools")
	fmt.Println()

	toolResults := make([]ToolResult, len(enabledTools))
	wg := sync.WaitGroup{}

	for i, tool := range enabledTools {
		wg.Add(1)
		go func(idx int, t ToolDef) {
			defer wg.Done()
			result := runTool(t, target, cfg, kr)
			toolResults[idx] = result
			printToolDone(result)
		}(i, tool)
	}
	wg.Wait()

	// ── Merge results ─────────────────────────
	sectionHdr("merging results")
	merged := mergeResults(toolResults)

	totalRaw := len(merged)
	inf(fmt.Sprintf("collected %s%d%s unique subdomains before resolution", white, totalRaw, reset))

	// ── Resolve IPs ───────────────────────────
	sectionHdr("resolving ips")
	fmt.Printf(gray+"  resolving %d subdomains with 50 concurrent resolvers...\n"+reset, totalRaw)

	allSubs := make([]string, 0, len(merged))
	for sub := range merged {
		allSubs = append(allSubs, sub)
	}
	sort.Strings(allSubs)

	resolvedMap := resolveAll(allSubs)

	// ── Build final entries ───────────────────
	sectionHdr("results")
	fmt.Printf("\n  %s%-3s  %-45s  %-18s  %s%s\n",
		dkgray, "no.", "subdomain", "ip", "source(s)", reset)
	fmt.Println(dkgray + "  " + strings.Repeat("─", 90) + reset)

	var resolvedEntries []SubdomainEntry
	var unresolvedEntries []SubdomainEntry

	for _, sub := range allSubs {
		ips := resolvedMap[sub]
		sources := merged[sub]
		entry := SubdomainEntry{
			Subdomain: sub,
			IPs:       ips,
			Sources:   sources,
			Resolved:  ips != nil,
		}
		if entry.Resolved {
			resolvedEntries = append(resolvedEntries, entry)
			printResultRow(entry)
		} else {
			unresolvedEntries = append(unresolvedEntries, entry)
		}
	}

	// ── Write output files ────────────────────
	allEntries := append(resolvedEntries, unresolvedEntries...)
	if err := writeOutputs(target, cfg.Settings.OutputDir, allEntries); err != nil {
		err_("failed to write output: " + err.Error())
	}

	// ── Final report ──────────────────────────
	elapsed := time.Since(start).Round(time.Second)
	divider()

	totalResolved := len(resolvedEntries)
	totalUnresolved := len(unresolvedEntries)

	fmt.Println()
	fmt.Printf("  %s%-22s%s %s%d%s\n", gray, "subdomains found", reset, white, totalRaw, reset)
	fmt.Printf("  %s%-22s%s %s%d%s\n", gray, "resolved", reset, white, totalResolved, reset)
	fmt.Printf("  %s%-22s%s %s%d%s\n", gray, "unresolved (filtered)", reset, dkgray, totalUnresolved, reset)
	fmt.Printf("  %s%-22s%s %s%s%s\n", gray, "duration", reset, dkgray, elapsed, reset)
	fmt.Println()

	// tool summary
	fmt.Printf("  %sTOOL SUMMARY%s\n", dkgray, reset)
	for _, tr := range toolResults {
		if tr.Skipped {
			fmt.Printf("  %s%-22s%s %sskipped — %s%s\n",
				dkgray, tr.Tool, reset, dim, tr.SkipReason, reset)
			continue
		}
		status := gray + "ok" + reset
		if tr.Err != nil {
			status = white + "err" + reset
		}
		fmt.Printf("  %s%-22s%s %s  %s+%d%s  %s%s%s\n",
			gray, tr.Tool, reset,
			status,
			white, len(tr.Subdomains), reset,
			dkgray, tr.Duration.Round(time.Millisecond), reset,
		)
	}

	fmt.Println()
	fmt.Printf("  %s%-22s%s %s./output/%s/subdomains.txt%s\n",
		dkgray, "subdomains.txt", reset, white, target, reset)
	fmt.Printf("  %s%-22s%s %s./output/%s/verbose.csv%s\n",
		dkgray, "verbose.csv", reset, white, target, reset)
	fmt.Println()
}

