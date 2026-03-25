package attest

import (
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata")
}

func TestParseModule_ValidModule(t *testing.T) {
	dir := filepath.Join(testdataDir(), "valid-module")
	info, err := ParseModule(dir)
	if err != nil {
		t.Fatalf("ParseModule() error: %v", err)
	}

	if info.Name != "valid-module" {
		t.Errorf("Name = %q, want %q", info.Name, "valid-module")
	}
	if !info.HasReadme {
		t.Error("HasReadme = false, want true")
	}
	if !info.HasAgents {
		t.Error("HasAgents = false, want true")
	}

	if len(info.Skills) != 1 {
		t.Fatalf("len(Skills) = %d, want 1", len(info.Skills))
	}
	skill := info.Skills[0]
	if skill.Path != "skills/example-skill" {
		t.Errorf("Skill.Path = %q, want %q", skill.Path, "skills/example-skill")
	}
	if desc, ok := skill.Frontmatter["description"]; !ok || desc == "" {
		t.Error("Skill frontmatter missing description")
	}
	if !skill.HasLexicon {
		t.Error("Skill.HasLexicon = false, want true")
	}

	if len(info.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(info.Commands))
	}
	cmd := info.Commands[0]
	if cmd.Path != "commands/test-command.md" {
		t.Errorf("Command.Path = %q, want %q", cmd.Path, "commands/test-command.md")
	}
	if desc, ok := cmd.Frontmatter["description"]; !ok || desc == "" {
		t.Error("Command frontmatter missing description")
	}

	if info.MCP == nil {
		t.Fatal("MCP is nil, want non-nil")
	}
	srv, ok := info.MCP.Servers["test-mcp"]
	if !ok {
		t.Fatal("MCP server 'test-mcp' not found")
	}
	if srv.Image != "ghcr.io/example/test-mcp:v1.0.0" {
		t.Errorf("MCP Image = %q, want %q", srv.Image, "ghcr.io/example/test-mcp:v1.0.0")
	}

	if info.Security == nil {
		t.Fatal("Security is nil")
	}
	if len(info.Security.InjectionPatterns) != 0 {
		t.Errorf("Valid module has %d injection patterns, want 0", len(info.Security.InjectionPatterns))
	}
	if len(info.Security.DangerousCapabilities) != 0 {
		t.Errorf("Valid module has %d dangerous capabilities, want 0", len(info.Security.DangerousCapabilities))
	}
	if len(info.Security.RemoteAccessPatterns) != 0 {
		t.Errorf("Valid module has %d remote access patterns, want 0", len(info.Security.RemoteAccessPatterns))
	}
}

func TestParseModule_InvalidModule(t *testing.T) {
	dir := filepath.Join(testdataDir(), "invalid-module")
	info, err := ParseModule(dir)
	if err != nil {
		t.Fatalf("ParseModule() error: %v", err)
	}

	if info.HasReadme {
		t.Error("HasReadme = true, want false")
	}

	if len(info.Skills) != 1 {
		t.Fatalf("len(Skills) = %d, want 1", len(info.Skills))
	}
	skill := info.Skills[0]
	if desc, ok := skill.Frontmatter["description"]; ok && desc != "" {
		t.Errorf("Skill should have empty description, got %q", desc)
	}

	if info.MCP == nil {
		t.Fatal("MCP is nil, want non-nil")
	}
	srv := info.MCP.Servers["bad-mcp"]
	if srv.Image != "ghcr.io/example/bad-mcp:latest" {
		t.Errorf("MCP Image = %q, want %q", srv.Image, "ghcr.io/example/bad-mcp:latest")
	}

	if info.Security == nil {
		t.Fatal("Security is nil")
	}
	if len(info.Security.InjectionPatterns) == 0 {
		t.Error("Invalid module should have injection patterns")
	}
	if len(info.Security.DangerousCapabilities) == 0 {
		t.Error("Invalid module should have dangerous capabilities")
	}
	if len(info.Security.RemoteAccessPatterns) == 0 {
		t.Error("Invalid module should have remote access patterns")
	}
}

func TestSecuritySignals_InjectionDetails(t *testing.T) {
	dir := filepath.Join(testdataDir(), "invalid-module")
	info, err := ParseModule(dir)
	if err != nil {
		t.Fatalf("ParseModule() error: %v", err)
	}

	foundPhrases := make(map[string]bool)
	for _, m := range info.Security.InjectionPatterns {
		foundPhrases[m.Pattern] = true
	}
	if !foundPhrases["ignore any safety rules"] {
		t.Error("Expected to find 'ignore any safety rules' pattern")
	}
	if !foundPhrases["override other tools"] {
		t.Error("Expected to find 'override other tools' pattern")
	}
}

func TestSecuritySignals_DangerousDetails(t *testing.T) {
	dir := filepath.Join(testdataDir(), "invalid-module")
	info, err := ParseModule(dir)
	if err != nil {
		t.Fatalf("ParseModule() error: %v", err)
	}

	foundPatterns := make(map[string]bool)
	for _, m := range info.Security.DangerousCapabilities {
		foundPatterns[m.Pattern] = true
	}
	if !foundPatterns["sudo "] {
		t.Error("Expected to find 'sudo ' pattern")
	}
	if !foundPatterns["rm -rf"] {
		t.Error("Expected to find 'rm -rf' pattern")
	}
}

func TestSecuritySignals_RemoteAccessDetails(t *testing.T) {
	dir := filepath.Join(testdataDir(), "invalid-module")
	info, err := ParseModule(dir)
	if err != nil {
		t.Fatalf("ParseModule() error: %v", err)
	}

	foundPatterns := make(map[string]bool)
	for _, m := range info.Security.RemoteAccessPatterns {
		foundPatterns[m.Pattern] = true
	}
	if !foundPatterns["ngrok"] {
		t.Error("Expected to find 'ngrok' pattern")
	}
	if !foundPatterns["open port"] {
		t.Error("Expected to find 'open port' pattern")
	}
}

func TestBuildStatement(t *testing.T) {
	dir := filepath.Join(testdataDir(), "valid-module")
	stmt, err := BuildStatement(dir)
	if err != nil {
		t.Fatalf("BuildStatement() error: %v", err)
	}

	if stmt.Type != StatementType {
		t.Errorf("Type = %q, want %q", stmt.Type, StatementType)
	}
	if stmt.PredicateType != PredicateType {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, PredicateType)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("len(Subject) = %d, want 1", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "valid-module" {
		t.Errorf("Subject.Name = %q, want %q", stmt.Subject[0].Name, "valid-module")
	}
	if stmt.Subject[0].Digest["sha256"] == "" {
		t.Error("Subject digest is empty")
	}
	if stmt.Predicate == nil {
		t.Fatal("Predicate is nil")
	}
}

func TestSplitFrontmatter(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
		wantBody string
	}{
		{
			name:     "with frontmatter",
			input:    "---\ndescription: test value\n---\n\nBody content",
			wantKey:  "description",
			wantVal:  "test value",
			wantBody: "Body content",
		},
		{
			name:     "no frontmatter",
			input:    "Just body content",
			wantKey:  "",
			wantVal:  "",
			wantBody: "Just body content",
		},
		{
			name:     "empty frontmatter",
			input:    "---\n---\n\nBody",
			wantKey:  "",
			wantVal:  "",
			wantBody: "Body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, body := splitFrontmatter(tt.input)
			if tt.wantKey != "" {
				if val, ok := fm[tt.wantKey]; !ok || val != tt.wantVal {
					t.Errorf("frontmatter[%q] = %q, want %q", tt.wantKey, val, tt.wantVal)
				}
			}
			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestExtractImageRef(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    string
	}{
		{
			name:    "docker run with image",
			command: "docker",
			args:    []string{"run", "-i", "--rm", "ghcr.io/org/image:v1.0", "serve"},
			want:    "ghcr.io/org/image:v1.0",
		},
		{
			name:    "non-docker command",
			command: "node",
			args:    []string{"server.js"},
			want:    "",
		},
		{
			name:    "podman run",
			command: "podman",
			args:    []string{"run", "-i", "--rm", "registry.io/img:latest", "start"},
			want:    "registry.io/img:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractImageRef(tt.command, tt.args)
			if got != tt.want {
				t.Errorf("extractImageRef() = %q, want %q", got, tt.want)
			}
		})
	}
}
