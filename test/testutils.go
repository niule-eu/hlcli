// Package testutils provides shared test utilities for the hlcli project
// This package contains helper functions and mock implementations for testing
package testutils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type SopsExecEnvironment struct {
	EnvVars                      map[string]string
	Cwd                          string
	EncryptedKeys                []string
	PartiallyEncryptedPathPrefix string
}

func (ee *SopsExecEnvironment) GetYamlPath() string {
	return filepath.Join(ee.Cwd, uuid.NewString()+".yaml")
}

func (ee *SopsExecEnvironment) GetJsonPath() string {
	return filepath.Join(ee.Cwd, uuid.NewString()+".json")
}

func (ee *SopsExecEnvironment) GetPartiallyEncryptedYamlPath() string {
	return filepath.Join(ee.Cwd, ee.PartiallyEncryptedPathPrefix+uuid.NewString()+".yaml")
}

func (ee *SopsExecEnvironment) GetPartiallyEncryptedJsonPath() string {
	return filepath.Join(ee.Cwd, ee.PartiallyEncryptedPathPrefix+uuid.NewString()+".json")
}

func NewSopsExecEnv(t *testing.T) *SopsExecEnvironment {
	t.Helper()

	publicKey, secretKey, err := generateAgeKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate age key pair: %v", err)
	}

	sopsConfig := fmt.Sprintf(`creation_rules:
  - path_regex: '.*hlcli-test.*\.json'
    encrypted_regex: '^(data|stringData)$'
    age: '%s'
  - path_regex: '.*hlcli-test.*\.yaml'
    encrypted_regex: '^(data|stringData)$'
    age: '%s'
  - age: '%s'
`, publicKey, publicKey, publicKey)

	tempDir := t.TempDir()

	tempSopsConfigFile := filepath.Join(tempDir, ".sops.yaml")

	t.Log(tempSopsConfigFile)
	if err := os.WriteFile(tempSopsConfigFile, []byte(sopsConfig), 0600); err != nil {
		t.Fatalf("Failed to create temporary .sops.yaml file: %v", err)
	}

	envVars := map[string]string{
		"SOPS_CONFIG":         tempSopsConfigFile,
		"SOPS_AGE_KEY":        secretKey,
		"SOPS_AGE_RECIPIENTS": "", // Clear recipients to use key directly
	}

	return &SopsExecEnvironment{
		EnvVars:                      envVars,
		Cwd:                          tempDir,
		EncryptedKeys:                []string{"data", "stringData"},
		PartiallyEncryptedPathPrefix: "hlcli-test",
	}
}

func generateAgeKeyPair() (string, string, error) {
	cmd := exec.Command("age-keygen")
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Execute the command
	err := cmd.Run()
	if err != nil {
		return "", "", fmt.Errorf("age-keygen command failed: %w, stderr: %s", err, stderrBuf.String())
	}

	// Parse the output to extract the public key
	// age-keygen output format:
	// # public key: age1...
	// AGE-SECRET-KEY-1...
	output := stdoutBuf.String()
	lines := strings.Split(output, "\n")
	var publicKey string
	var secretKey string

	for _, line := range lines {
		if strings.HasPrefix(line, "# public key: ") {
			publicKey = strings.TrimPrefix(line, "# public key: ")
		} else if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			secretKey = strings.TrimSpace(line)
		}
	}

	// Validate that we got both keys
	if publicKey == "" || secretKey == "" {
		return "", "", fmt.Errorf("age-keygen output parsing failed: publicKey='%s', secretKey='%s', output='%s'",
			publicKey, secretKey, output)
	}

	return publicKey, secretKey, nil
}

// CreateTempFile creates a temporary file with the given content and returns its path
// The file is automatically cleaned up when the test completes
func CreateTempFile(t *testing.T, content string) string {
	t.Helper()

	tempFile, err := os.CreateTemp("", "hlcli-test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tempFile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	t.Cleanup(func() {
		os.Remove(tempFile.Name())
	})

	return tempFile.Name()
}

// CreateTempDir creates a temporary directory and returns its path
// The directory is automatically cleaned up when the test completes
func CreateTempDir(t *testing.T) string {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "hlcli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return tempDir
}

// CreateTestFileInDir creates a file with the given content in the specified directory
func CreateTestFileInDir(t *testing.T, dir, filename, content string) string {
	t.Helper()

	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file %s: %v", filePath, err)
	}

	return filePath
}

// FileExists checks if a file exists at the given path
func FileExists(t *testing.T, path string) bool {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatalf("Error checking file existence: %v", err)
	}

	return !info.IsDir()
}

// DirExists checks if a directory exists at the given path
func DirExists(t *testing.T, path string) bool {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatalf("Error checking directory existence: %v", err)
	}

	return info.IsDir()
}
