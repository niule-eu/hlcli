package framework

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFileWriteIO(t *testing.T) {
	content := []byte("test content")

	t.Run("writes content to file", func(t *testing.T) {
		tempFile := "test_output.txt"
		defer os.Remove(tempFile)
		// Test
		effect := NewDefaultFileWriteIO(tempFile, &content)
		err := effect.Apply()

		// Verify
		if err != nil {
			t.Fatalf("Apply() failed: %v", err)
		}

		// Check file content
		fileContent, err := os.ReadFile(tempFile)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		if string(fileContent) != string(content) {
			t.Errorf("Expected content '%s', got '%s'", content, fileContent)
		}
	})

	t.Run("handles file permissions", func(t *testing.T) {
		tempFile := "test_permissions.txt"
		defer os.Remove(tempFile)
		// Test
		effect := &FileWriteIO{
			Path:        tempFile,
			Content:     &content,
			Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
			Permissions: 0600,
		}
		err := effect.Apply()

		// Verify
		if err != nil {
			t.Fatalf("Apply() failed: %v", err)
		}

		// Check file permissions
		info, err := os.Stat(tempFile)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}

		expectedMode := os.FileMode(0600)
		if info.Mode().Perm() != expectedMode {
			t.Errorf("Expected permissions %v, got %v", expectedMode, info.Mode().Perm())
		}
	})
}

func TestCompoundEffect(t *testing.T) {
	content1 := []byte("first")
	content2 := []byte("second")
	file1 := "test_compound1.txt"
	file2 := "test_compound2.txt"
	defer os.Remove(file1)
	defer os.Remove(file2)

	t.Run("executes multiple effects in order", func(t *testing.T) {
		// Setup

		// Test
		compound := CompoundEffect{
			Effects: []Effect{
				NewDefaultFileWriteIO(file1, &content1),
				NewDefaultFileWriteIO(file2, &content2),
			},
		}
		err := compound.Apply()

		// Verify
		if err != nil {
			t.Fatalf("Apply() failed: %v", err)
		}

		// Check both files were created
		if _, err := os.Stat(file1); err != nil {
			t.Errorf("File1 not created: %v", err)
		}
		if _, err := os.Stat(file2); err != nil {
			t.Errorf("File2 not created: %v", err)
		}
	})

	t.Run("reports errors from individual effects", func(t *testing.T) {
		// Setup
		invalidPath := "/invalid/path/file.txt"

		// Test
		compound := CompoundEffect{
			Effects: []Effect{
				NewDefaultFileWriteIO(file1, &content1),
				NewDefaultFileWriteIO(invalidPath, &content2), // This should fail
			},
		}
		err := compound.Apply()

		// Verify error occurred
		if err == nil {
			t.Error("Expected error from invalid path, got nil")
		}
	})
}

func TestNoOp(t *testing.T) {
	t.Run("does nothing and returns no error", func(t *testing.T) {
		effect := &NoOp{}
		err := effect.Apply()
		if err != nil {
			t.Errorf("NoOp.Apply() returned error: %v", err)
		}
	})
}

func TestStdOutIO(t *testing.T) {
	t.Run("writes to stdout", func(t *testing.T) {
		// This is more of a smoke test since we can't easily capture stdout
		// in a way that works across different testing environments
		msg := "test message"
		effect := NewStdOutIO(msg)
		err := effect.Apply()
		if err != nil {
			t.Errorf("StdOutIO.Apply() returned error: %v", err)
		}
	})
}

func TestSopsEncryptEffect(t *testing.T) {

	publicKey, secretKey, err := generateAgeKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate age key pair: %v", err)
	}

	// Create a temporary .sops.yaml file with the freshly generated public key
	// Include path_regex and encrypted_regex rules
	sopsConfig := fmt.Sprintf(`creation_rules:
  - path_regex: '.*hlcli-test.*\.json'
    encrypted_regex: '^(data|stringData)$'
    age: '%s'
  - path_regex: '.*hlcli-test.*\.yaml'
    encrypted_regex: '^(data|stringData)$'
    age: '%s'
  - age: '%s'
`, publicKey, publicKey, publicKey)
	tempSopsConfigFile := "temp_test_sops.yaml"
	if err := os.WriteFile(tempSopsConfigFile, []byte(sopsConfig), 0600); err != nil {
		t.Fatalf("Failed to create temporary .sops.yaml file: %v", err)
	}
	defer os.Remove(tempSopsConfigFile)

	envVars := map[string]string{
		"SOPS_AGE_KEY":        secretKey,
		"SOPS_AGE_RECIPIENTS": "", // Clear recipients to use key directly
	}

	t.Run("successfully encrypts using local exec environment", func(t *testing.T) {
		// Setup - check if SOPS_AGE_KEY or SOPS_AGE_KEY_FILE are set
		ageKey := os.Getenv("SOPS_AGE_KEY")
		ageKeyFile := os.Getenv("SOPS_AGE_KEY_FILE")

		// If no age key is available, create a temporary one using the generated key
		var tempKeyFile string
		var cleanupFunc func()

		if ageKey == "" && ageKeyFile == "" {
			// Check if ~/.config/sops/age/keys.txt already exists
			homeDir, err := os.UserHomeDir()
			if err != nil {
				t.Fatalf("Failed to get user home directory: %v", err)
			}

			existingKeyFile := homeDir + "/.config/sops/age/keys.txt"
			if _, err := os.Stat(existingKeyFile); os.IsNotExist(err) {
				// Create temporary keys file with the generated secret key
				tempKeyFile = existingKeyFile
				if err := os.MkdirAll(homeDir+"/.config/sops/age", 0755); err != nil {
					t.Fatalf("Failed to create sops age directory: %v", err)
				}

				if err := os.WriteFile(tempKeyFile, []byte(secretKey), 0600); err != nil {
					t.Fatalf("Failed to write temporary key file: %v", err)
				}

				cleanupFunc = func() {
					os.Remove(tempKeyFile)
					os.Remove(homeDir + "/.config/sops/age")
					os.Remove(homeDir + "/.config/sops")
				}
				defer cleanupFunc()
			}
		}

		// Setup - use valid JSON content
		content := []byte(`{"test": "content", "data": "sensitive"}`)
		originalContent := string(content)
		effect := NewSopsEncryptEffect(&content, "", "test.json", nil)

		// Test
		err := effect.Apply()

		// Verify - should succeed since sops is available
		if err != nil {
			t.Fatalf("Expected successful encryption, got error: %v", err)
		}

		// Verify content was modified (encrypted)
		if string(content) == originalContent {
			t.Error("Expected content to be encrypted, but it remained unchanged")
		}

		// Verify encrypted content contains expected SOPS structure
		encryptedStr := string(content)
		if !bytes.Contains(content, []byte("sops")) {
			t.Errorf("Expected encrypted content to contain 'sops' metadata, got: %s", encryptedStr)
		}
		if !bytes.Contains(content, []byte("ENC[AES256_GCM")) {
			t.Errorf("Expected encrypted content to contain encrypted data, got: %s", encryptedStr)
		}
	})

	t.Run("assert handles invalid JSON content gracefully", func(t *testing.T) {
		// Setup - use invalid JSON content
		content := []byte("not valid json")
		originalContent := string(content)
		effect := NewSopsEncryptEffect(&content, "", "test.json", envVars)

		// Test
		err := effect.Apply()

		// Verify - should fail due to invalid JSON
		if err == nil {
			t.Error("Expected error for invalid JSON content, got nil")
		}

		// Verify original content is preserved on error
		if string(content) != originalContent {
			t.Errorf("Expected original content preserved on error, got: %s", content)
		}
	})

	t.Run("assert handles empty content", func(t *testing.T) {
		// Setup
		content := []byte("{}") // Empty JSON object
		effect := NewSopsEncryptEffect(&content, "", "empty.json", envVars)

		// Test
		err := effect.Apply()

		// Verify - should succeed with empty JSON
		if err != nil {
			t.Fatalf("Expected successful encryption of empty JSON, got error: %v", err)
		}

		// Verify content was modified (encrypted)
		if bytes.Equal(content, []byte("{}")) {
			t.Error("Expected empty JSON to be encrypted, but it remained unchanged")
		}
	})

	t.Run("assert real SOPS encryption workflow", func(t *testing.T) {
		// Setup - realistic sensitive data
		content := []byte(`{
			"database": {
				"username": "admin",
				"password": "super-secret-password",
				"host": "db.example.com"
			},
			"api_keys": {
				"stripe": "sk_live_abc123",
				"aws": "AKIAIOSFODNN7EXAMPLE"
			}
		}`)
		originalContent := string(content)
		effect := NewSopsEncryptEffect(&content, "", "secrets.json", envVars)

		// Test
		err := effect.Apply()

		// Verify
		if err != nil {
			t.Fatalf("Expected successful encryption of sensitive data, got error: %v", err)
		}

		// Verify content was encrypted
		if string(content) == originalContent {
			t.Error("Expected sensitive data to be encrypted, but it remained unchanged")
		}

		// Verify encrypted content has expected structure
		encryptedStr := string(content)
		if !bytes.Contains(content, []byte("sops")) {
			t.Errorf("Expected encrypted content to contain SOPS metadata")
		}
		if !bytes.Contains(content, []byte("ENC[AES256_GCM")) {
			t.Errorf("Expected encrypted content to contain encrypted data markers")
		}
		if !bytes.Contains(content, []byte("age")) {
			t.Errorf("Expected encrypted content to contain encryption key info")
		}

		// Log a sample of the encrypted output for demonstration
		runLength := len(encryptedStr)
		if runLength > 150 {
			runLength = 150
		}
		t.Logf("Encrypted output sample (%d bytes): %s...", len(encryptedStr), encryptedStr[:runLength])
	})

	t.Run("assert filename overrides function", func(t *testing.T) {
		// Test with YAML filename override
		yamlContent := []byte(`apiVersion: v1
kind: Secret
data:
password: cGFzc3dvcmQ=
`)
		yamlEffect := NewSopsEncryptEffect(&yamlContent, "", "secret.yaml", envVars)
		err := yamlEffect.Apply()
		if err != nil {
			t.Fatalf("Expected successful YAML encryption, got error: %v", err)
		}

		// Verify YAML was encrypted
		if !bytes.Contains(yamlContent, []byte("kind:")) {
			t.Errorf("Expected YAML content")
		}
		if !bytes.Contains(yamlContent, []byte("ENC[AES256_GCM")) {
			t.Errorf("Expected ecrypted content")
		}

		// Test with JSON filename override
		jsonContent := []byte(`{"api_key": "secret123", "token": "sensitive"}`)
		jsonEffect := NewSopsEncryptEffect(&jsonContent, "", "config.json", envVars)
		err = jsonEffect.Apply()
		if err != nil {
			t.Fatalf("Expected successful JSON encryption, got error: %v", err)
		}

		// Verify JSON was encrypted
		if !bytes.Contains(jsonContent, []byte("\"api_key\":")) {
			t.Errorf("Expected JSON content")
		}
		if !bytes.Contains(yamlContent, []byte("ENC[AES256_GCM")) {
			t.Errorf("Expected ecrypted content")
		}

	})

	t.Run("Assert .sops.yaml config file used", func(t *testing.T) {
		// Test content to encrypt using the config file
		content := []byte(`{
				"config_test": "this is encrypted using a .sops.yaml config file",
				"sensitive_info": "encrypted with the generated public key",
				"data": "foo"
			}`)
		originalContent := string(content)

		// Create effect using the temporary config file
		effect := NewSopsEncryptEffect(&content, tempSopsConfigFile, "hlcli-test.json", envVars)

		// Apply encryption
		err := effect.Apply()
		if err != nil {
			t.Fatalf("Failed to encrypt with .sops.yaml config: %v", err)
		}

		// Verify content was encrypted
		if string(content) == originalContent {
			t.Error("Expected content to be encrypted with config file, but it remained unchanged")
		}

		// Verify encrypted content structure
		if !bytes.Contains(content, []byte("sops")) {
			t.Errorf("Expected encrypted content to contain SOPS metadata")
		}
		if !bytes.Contains(content, []byte("\"config_test\": \"this")) {
			t.Errorf("Expected value for key 'config-test' to be unencrypted")
		}
		if !bytes.Contains(content, []byte("\"data\": \"ENC[AES256_GCM")) {
			t.Errorf("Expected value for key 'data' to be encrypted")
		}
		if !bytes.Contains(content, []byte("age")) {
			t.Errorf("Expected encrypted content to contain age encryption info")
		}
		t.Logf("Successfully encrypted with .sops.yaml config:\n %s", sopsConfig)
		t.Logf("Used public key: %s", publicKey)
	})

	t.Run("tests compound effect with SopsEncryptEffect followed by FileWriteIO", func(t *testing.T) {
		// Test content to encrypt and then write to file
		content := []byte(`{
				"database": {
					"username": "admin",
					"password": "super-secret-password"
				},
				"api_keys": {
					"stripe": "sk_live_test123",
					"aws": "AKIAIOSFODNN7EXAMPLE"
				}
			}`)
		originalContent := string(content)
		outputFile := "test_encrypted_output.json"
		defer os.Remove(outputFile)

		// Create compound effect: encrypt then write to file
		compoundEffect := CompoundEffect{
			Effects: []Effect{
				NewSopsEncryptEffect(&content, tempSopsConfigFile, "secrets.json", envVars),
				NewDefaultFileWriteIO(outputFile, &content),
			},
		}

		// Apply the compound effect
		err := compoundEffect.Apply()
		if err != nil {
			t.Fatalf("Compound effect failed: %v", err)
		}

		// Verify content was encrypted (not original plaintext)
		if string(content) == originalContent {
			t.Error("Expected content to be encrypted, but it remained unchanged")
		}

		// Verify encrypted content structure
		if !bytes.Contains(content, []byte("sops")) {
			t.Errorf("Expected encrypted content to contain SOPS metadata")
		}
		if !bytes.Contains(content, []byte("ENC[AES256_GCM")) {
			t.Errorf("Expected encrypted content to contain encrypted data markers")
		}

		// Verify the file was written
		if _, err := os.Stat(outputFile); err != nil {
			t.Errorf("Output file was not created: %v", err)
		}

		// Verify file content matches encrypted content
		fileContent, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		if !bytes.Equal(fileContent, content) {
			t.Errorf("File content does not match encrypted content")
		}

		// Verify the written file contains encrypted data (not plaintext)
		if bytes.Contains(fileContent, []byte("super-secret-password")) {
			t.Error("File contains plaintext password, should be encrypted")
		}
		if bytes.Contains(fileContent, []byte("sk_live_test123")) {
			t.Error("File contains plaintext API key, should be encrypted")
		}

		t.Logf("Successfully encrypted and wrote file (%d bytes)", len(fileContent))
	})
}

// generateAgeKeyPair generates a fresh age key pair for testing
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

// Test helper to create a byte slice reference for testing
func makeByteSliceRef(content string) *[]byte {
	result := []byte(content)
	return &result
}
