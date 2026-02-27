package framework

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	testutils "github.com/niule-eu/hlcli/test"
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

	execEnv := testutils.NewSopsExecEnv(t)

	t.Run("assert handles invalid JSON content gracefully", func(t *testing.T) {
		// Setup - use invalid JSON content
		content := []byte("not valid json")
		originalContent := string(content)
		tmpPath := execEnv.GetJsonPath()
		effect := NewSopsEncryptEffect(&content, "", tmpPath, execEnv.EnvVars)

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
		tmpPath := execEnv.GetJsonPath()
		effect := NewSopsEncryptEffect(&content, "", tmpPath, execEnv.EnvVars)

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
		tmpPath := execEnv.GetJsonPath()
		effect := NewSopsEncryptEffect(&content, "", tmpPath, execEnv.EnvVars)

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

	t.Run("Assert .sops.yaml config file used", func(t *testing.T) {
		// Test content to encrypt using the config file

		content := []byte(fmt.Sprintf(`{
				"config_test": "this is encrypted using a .sops.yaml config file",
				"sensitive_info": "encrypted with the generated public key",
				"%s": "foo"
			}`, execEnv.EncryptedKeys[0]))
		originalContent := string(content)
		tmpPath := execEnv.GetPartiallyEncryptedJsonPath()

		// Create effect using the temporary config file
		effect := NewSopsEncryptEffect(&content, "", tmpPath, execEnv.EnvVars)

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
		tmpPath := execEnv.GetJsonPath()

		// Create compound effect: encrypt then write to file
		compoundEffect := CompoundEffect{
			Effects: []Effect{
				NewSopsEncryptEffect(&content, "", tmpPath, execEnv.EnvVars),
				NewDefaultFileWriteIO(tmpPath, &content),
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
		if _, err := os.Stat(tmpPath); err != nil {
			t.Errorf("Output file was not created: %v", err)
		}

		// Verify file content matches encrypted content
		fileContent, err := os.ReadFile(tmpPath)
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
