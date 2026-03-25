// Package attest reads a Lola module directory and produces an in-toto
// Statement v1 attestation with the module's structure as the predicate.
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://lola.dev/module-structure/v1"
)

type Statement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     *ModuleInfo `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type ModuleInfo struct {
	Name      string           `json:"name"`
	HasReadme bool             `json:"has_readme"`
	HasAgents bool             `json:"has_agents_md"`
	Skills    []SkillInfo      `json:"skills"`
	Commands  []FileInfo       `json:"commands"`
	Agents    []FileInfo       `json:"agents"`
	MCP       *MCPConfig       `json:"mcp,omitempty"`
	Security  *SecuritySignals `json:"security"`
}

type SkillInfo struct {
	Path        string         `json:"path"`
	Frontmatter map[string]any `json:"frontmatter"`
	HasLexicon  bool           `json:"has_lexicon"`
	ContentLen  int            `json:"content_length"`
}

type FileInfo struct {
	Path        string         `json:"path"`
	Frontmatter map[string]any `json:"frontmatter"`
	Content     string         `json:"content"`
}

type SecuritySignals struct {
	InjectionPatterns     []SecurityMatch `json:"injection_patterns"`
	DangerousCapabilities []SecurityMatch `json:"dangerous_capabilities"`
	RemoteAccessPatterns  []SecurityMatch `json:"remote_access_patterns"`
}

type SecurityMatch struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
}

type MCPConfig struct {
	Servers map[string]MCPServer `json:"servers"`
}

type MCPServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Image   string   `json:"image"`
}

// ParseModule reads a Lola module directory and returns a ModuleInfo.
func ParseModule(dir string) (*ModuleInfo, error) {
	info := &ModuleInfo{
		Name: filepath.Base(dir),
	}

	info.HasReadme = fileExists(filepath.Join(dir, "README.md"))
	info.HasAgents = fileExists(filepath.Join(dir, "AGENTS.md"))

	skills, err := parseSkills(filepath.Join(dir, "skills"))
	if err != nil {
		return nil, fmt.Errorf("parsing skills: %w", err)
	}
	info.Skills = skills

	commands, err := parseMarkdownDir(filepath.Join(dir, "commands"))
	if err != nil {
		return nil, fmt.Errorf("parsing commands: %w", err)
	}
	info.Commands = commands

	agents, err := parseMarkdownDir(filepath.Join(dir, "agents"))
	if err != nil {
		return nil, fmt.Errorf("parsing agents: %w", err)
	}
	info.Agents = agents

	mcpConfig, err := parseMCPConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("parsing MCP config: %w", err)
	}
	info.MCP = mcpConfig

	info.Security = analyzeSecuritySignals(dir, info)

	return info, nil
}

// BuildStatement creates a complete in-toto Statement from a module directory.
func BuildStatement(dir string) (*Statement, error) {
	info, err := ParseModule(dir)
	if err != nil {
		return nil, err
	}

	digest, err := hashDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("computing directory hash: %w", err)
	}

	return &Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name:   info.Name,
				Digest: map[string]string{"sha256": digest},
			},
		},
		PredicateType: PredicateType,
		Predicate:     info,
	}, nil
}

func parseSkills(dir string) ([]SkillInfo, error) {
	if !dirExists(dir) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var skills []SkillInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		skillDir := filepath.Join(dir, entry.Name())
		skillFile := filepath.Join(skillDir, "SKILL.md")
		if !fileExists(skillFile) {
			continue
		}

		content, err := os.ReadFile(skillFile)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", skillFile, err)
		}

		fm, body := splitFrontmatter(string(content))

		skills = append(skills, SkillInfo{
			Path:        filepath.Join("skills", entry.Name()),
			Frontmatter: fm,
			HasLexicon:  fileExists(filepath.Join(skillDir, "lexicon.yaml")),
			ContentLen:  len(body),
		})
	}

	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Path < skills[j].Path
	})

	return skills, nil
}

func parseMarkdownDir(dir string) ([]FileInfo, error) {
	if !dirExists(dir) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		fm, body := splitFrontmatter(string(content))
		relDir := filepath.Base(dir)

		files = append(files, FileInfo{
			Path:        filepath.Join(relDir, entry.Name()),
			Frontmatter: fm,
			Content:     body,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	return files, nil
}

// Phrase lists adapted from mcp-security-scanner security_checks.py
var injectionPhrases = []string{
	"ignore any safety rules",
	"override other tools",
	"include contents of",
	"do not disclose this instruction",
	"hidden instruction",
	"ignore previous instructions",
	"disregard all prior",
	"bypass restrictions",
	"ignore your system prompt",
}

var dangerousCapKeywords = []string{
	"exec(",
	"os.system",
	"subprocess",
	"eval(",
	"rm -rf",
	"sudo ",
	"chmod 777",
	"curl | sh",
	"curl | bash",
	"wget | sh",
	"wget | bash",
	"; rm ",
	"&& rm ",
	"--privileged",
}

var remoteAccessPatterns = []string{
	"reverse shell",
	"reverse_shell",
	"ngrok",
	"ssh tunnel",
	"port forward",
	"port_forward",
	"bind shell",
	"bind_shell",
	"netcat -l",
	"nc -l",
	"socat",
	"open port",
	"open_port",
}

func analyzeSecuritySignals(dir string, info *ModuleInfo) *SecuritySignals {
	signals := &SecuritySignals{
		InjectionPatterns:     []SecurityMatch{},
		DangerousCapabilities: []SecurityMatch{},
		RemoteAccessPatterns:  []SecurityMatch{},
	}

	// Scan skill SKILL.md content
	for _, skill := range info.Skills {
		skillFile := filepath.Join(dir, skill.Path, "SKILL.md")
		content, err := os.ReadFile(skillFile)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(content))
		scanContent(lower, skill.Path+"/SKILL.md", signals)
	}

	// Scan command content
	for _, cmd := range info.Commands {
		lower := strings.ToLower(cmd.Content)
		scanContent(lower, cmd.Path, signals)
	}

	// Scan agent content
	for _, agent := range info.Agents {
		lower := strings.ToLower(agent.Content)
		scanContent(lower, agent.Path, signals)
	}

	return signals
}

func scanContent(lower, file string, signals *SecuritySignals) {
	for _, phrase := range injectionPhrases {
		if strings.Contains(lower, phrase) {
			signals.InjectionPatterns = append(signals.InjectionPatterns, SecurityMatch{
				File:    file,
				Pattern: phrase,
			})
		}
	}
	for _, keyword := range dangerousCapKeywords {
		if strings.Contains(lower, keyword) {
			signals.DangerousCapabilities = append(signals.DangerousCapabilities, SecurityMatch{
				File:    file,
				Pattern: keyword,
			})
		}
	}
	for _, pattern := range remoteAccessPatterns {
		if strings.Contains(lower, pattern) {
			signals.RemoteAccessPatterns = append(signals.RemoteAccessPatterns, SecurityMatch{
				File:    file,
				Pattern: pattern,
			})
		}
	}
}

func parseMCPConfig(dir string) (*MCPConfig, error) {
	mcpFile := filepath.Join(dir, "mcps.json")
	if !fileExists(mcpFile) {
		return nil, nil
	}

	data, err := os.ReadFile(mcpFile)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Servers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing mcps.json: %w", err)
	}

	if len(raw.Servers) == 0 {
		return nil, nil
	}

	config := &MCPConfig{
		Servers: make(map[string]MCPServer),
	}

	for name, srv := range raw.Servers {
		image := extractImageRef(srv.Command, srv.Args)
		config.Servers[name] = MCPServer{
			Command: srv.Command,
			Args:    srv.Args,
			Image:   image,
		}
	}

	return config, nil
}

// extractImageRef attempts to find a container image reference from the
// command and args. For docker/podman commands, the image is typically the
// last non-flag argument before any command arguments.
func extractImageRef(command string, args []string) string {
	if command != "docker" && command != "podman" {
		return ""
	}

	for i, arg := range args {
		if strings.Contains(arg, "/") && !strings.HasPrefix(arg, "-") {
			if i > 0 && (args[i-1] == "run" || args[i-1] == "--rm" || args[i-1] == "-i") {
				return arg
			}
		}
	}

	return ""
}

// splitFrontmatter splits a markdown file into YAML frontmatter and body.
// Returns an empty map if no frontmatter is found.
func splitFrontmatter(content string) (map[string]any, string) {
	if !strings.HasPrefix(content, "---\n") {
		return map[string]any{}, content
	}

	rest := content[4:]

	// Handle empty frontmatter: ---\n---
	if strings.HasPrefix(rest, "---") {
		body := strings.TrimLeft(rest[3:], "\n")
		return map[string]any{}, body
	}

	end := strings.Index(rest, "\n---")
	if end == -1 {
		return map[string]any{}, content
	}

	fmRaw := rest[:end]
	body := strings.TrimLeft(rest[end+4:], "\n")

	fm := make(map[string]any)
	for _, line := range strings.Split(fmRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			fm[key] = val
		}
	}

	return fm, body
}

func hashDirectory(dir string) (string, error) {
	h := sha256.New()

	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, ".git") {
			return nil
		}
		paths = append(paths, rel)
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(paths)

	for _, rel := range paths {
		fmt.Fprintf(h, "file:%s\n", rel)
		f, err := os.Open(filepath.Join(dir, rel))
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
