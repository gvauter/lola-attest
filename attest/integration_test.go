package attest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func ampelBinary() string {
	if path, err := exec.LookPath("ampel"); err == nil {
		return path
	}
	return ""
}

func policiesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "policies")
}

func bundlePolicies(t *testing.T) string {
	t.Helper()
	dir := policiesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading policies dir: %v", err)
	}

	var policies []json.RawMessage
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading policy %s: %v", e.Name(), err)
		}
		policies = append(policies, data)
	}

	bundle := map[string]any{
		"id":       "lola-module-standards",
		"policies": policies,
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshaling policy bundle: %v", err)
	}

	bundleFile := filepath.Join(t.TempDir(), "policy-bundle.json")
	if err := os.WriteFile(bundleFile, bundleJSON, 0o644); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	return bundleFile
}

func writeAttestation(t *testing.T, moduleDir string) (attestFile string, subjectHash string) {
	t.Helper()
	stmt, err := BuildStatement(moduleDir)
	if err != nil {
		t.Fatalf("BuildStatement() error: %v", err)
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	attestFile = filepath.Join(t.TempDir(), "module.intoto.json")
	if err := os.WriteFile(attestFile, data, 0o644); err != nil {
		t.Fatalf("writing attestation: %v", err)
	}

	subjectHash = "sha256:" + stmt.Subject[0].Digest["sha256"]
	return
}

func TestIntegration_AmpelVerify_ValidModule(t *testing.T) {
	ampel := ampelBinary()
	if ampel == "" {
		t.Skip("ampel binary not found, skipping integration test")
	}

	attestFile, subjectHash := writeAttestation(t, filepath.Join(testdataDir(), "valid-module"))
	bundleFile := bundlePolicies(t)

	cmd := exec.Command(ampel, "verify",
		"--subject-hash", subjectHash,
		"-a", attestFile,
		"-p", bundleFile,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ampel verify failed for valid module:\n%s\nerror: %v", string(output), err)
	}
	t.Logf("ampel verify output for valid module:\n%s", string(output))
}

func TestIntegration_AmpelVerify_InvalidModule(t *testing.T) {
	ampel := ampelBinary()
	if ampel == "" {
		t.Skip("ampel binary not found, skipping integration test")
	}

	attestFile, subjectHash := writeAttestation(t, filepath.Join(testdataDir(), "invalid-module"))
	bundleFile := bundlePolicies(t)

	cmd := exec.Command(ampel, "verify",
		"--subject-hash", subjectHash,
		"-a", attestFile,
		"-p", bundleFile,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("ampel verify should have failed for invalid module, but succeeded:\n%s", string(output))
	}
	t.Logf("ampel verify correctly failed for invalid module:\n%s", string(output))
}

func TestIntegration_AmpelVerify_ResultsAttestation(t *testing.T) {
	ampel := ampelBinary()
	if ampel == "" {
		t.Skip("ampel binary not found, skipping integration test")
	}

	attestFile, subjectHash := writeAttestation(t, filepath.Join(testdataDir(), "valid-module"))
	bundleFile := bundlePolicies(t)
	resultsFile := filepath.Join(t.TempDir(), "results.intoto.json")

	cmd := exec.Command(ampel, "verify",
		"--subject-hash", subjectHash,
		"-a", attestFile,
		"-p", bundleFile,
		"--attest-results",
		"--results-path", resultsFile,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ampel verify failed:\n%s\nerror: %v", string(output), err)
	}

	resultsData, err := os.ReadFile(resultsFile)
	if err != nil {
		t.Fatalf("reading results file: %v", err)
	}

	var results map[string]any
	if err := json.Unmarshal(resultsData, &results); err != nil {
		t.Fatalf("parsing results JSON: %v", err)
	}

	if results["_type"] != "https://in-toto.io/Statement/v1" {
		t.Errorf("results _type = %v, want in-toto Statement v1", results["_type"])
	}
	t.Logf("Results attestation generated successfully (%d bytes)", len(resultsData))
}

func TestIntegration_AmpelVerify_EachPolicyIndividually(t *testing.T) {
	ampel := ampelBinary()
	if ampel == "" {
		t.Skip("ampel binary not found, skipping integration test")
	}

	attestFile, subjectHash := writeAttestation(t, filepath.Join(testdataDir(), "valid-module"))

	entries, err := os.ReadDir(policiesDir())
	if err != nil {
		t.Fatalf("reading policies dir: %v", err)
	}

	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			policyData, err := os.ReadFile(filepath.Join(policiesDir(), e.Name()))
			if err != nil {
				t.Fatalf("reading policy: %v", err)
			}

			bundle := map[string]any{
				"id":       "single-policy",
				"policies": []json.RawMessage{policyData},
			}
			bundleJSON, _ := json.Marshal(bundle)

			bundleFile := filepath.Join(t.TempDir(), "bundle.json")
			os.WriteFile(bundleFile, bundleJSON, 0o644)

			cmd := exec.Command(ampel, "verify",
				"--subject-hash", subjectHash,
				"-a", attestFile,
				"-p", bundleFile,
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Policy %s failed on valid module:\n%s", e.Name(), string(output))
			}
		})
	}
}
