package render

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/niule-eu/hlcli/pkg/framework"
	testutils "github.com/niule-eu/hlcli/test"
)

func TestRenderPklWithSopsEncryption(t *testing.T) {
	// Setup test environment

	execEnv := testutils.NewSopsExecEnv(t)

	testPklFile := filepath.Join(execEnv.Cwd, "test.pkl")
	tmpYamlFile1 := execEnv.GetPartiallyEncryptedYamlPath()
	tmpYamlFile2 := execEnv.GetPartiallyEncryptedYamlPath()

	// Create a simple PKL file for testing
	expectedYaml := fmt.Sprintf(`foo: bar
%s:
  baz: foo
`, execEnv.EncryptedKeys[0])

	testPklContent := fmt.Sprintf(`
%s = new {
  foo = "bar"
  data {
    baz = "foo"        
  }
}
output {
  value = data
  files {
    ["%s"] {
      value = data
      renderer = new YamlRenderer {}
    }
	["%s"] {
      value = data
      renderer = new YamlRenderer {}
    }
  }
  renderer = new YamlRenderer {}
}
	`, execEnv.EncryptedKeys[0], tmpYamlFile1, tmpYamlFile2)

	if err := os.WriteFile(testPklFile, []byte(testPklContent), 0644); err != nil {
		t.Fatalf("Failed to create test PKL file: %v", err)
	}

	// Test cases
	t.Run("RenderPkl without SOPS encryption", func(t *testing.T) {
		tmpFile := execEnv.GetYamlPath()
		// t.Log(tmpFile)
		params := RenderPklParams{
			PklFile:            testPklFile,
			OutputFile:         tmpFile,
			MultipleFileOutput: false,
			EncryptWithSops:    false,
		}

		secrets := koanf.New(".")
		effects, err := RenderPkl(params, secrets)
		if err != nil {
			t.Fatalf("RenderPkl failed: %v", err)
		}

		// Should have one FileWriteIO effect
		if len(effects) != 1 {
			t.Errorf("Expected 1 effect, got %d", len(effects))
		}

		// Execute the effect
		for _, effect := range effects {
			if err := effect.Apply(); err != nil {
				t.Fatalf("Effect execution failed: %v", err)
			}
		}

		// Verify output file was created and contains expected YAML content
		content, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		// Expect proper YAML formatting with the PKL output structure
		if !bytes.Contains(content, []byte(expectedYaml)) {
			t.Errorf("Expected YAML output to contain:\n%s\ngot:\n%s", expectedYaml, content)
		}
	})

	t.Run("RenderPkl with SOPS encryption flag", func(t *testing.T) {
		// Check if SOPS is available
		if _, err := exec.LookPath("sops"); err != nil {
			t.Skip("SOPS binary not available, skipping SOPS encryption test")
		}

		tmpFile := execEnv.GetYamlPath()

		params := RenderPklParams{
			PklFile:            testPklFile,
			OutputFile:         tmpFile,
			MultipleFileOutput: false,
			EncryptWithSops:    true,
			EnvVars:            execEnv.EnvVars,
		}

		secrets := koanf.New(".")
		effects, err := RenderPkl(params, secrets)
		if err != nil {
			t.Fatalf("RenderPkl failed: %v", err)
		}

		// Should have one CompoundEffect containing encryption + write
		if len(effects) != 1 {
			t.Errorf("Expected 1 effect, got %d", len(effects))
		}

		// Verify it's a CompoundEffect
		compound, ok := effects[0].(framework.CompoundEffect)
		if !ok {
			t.Errorf("Expected CompoundEffect, got %T", effects[0])
		}

		// Should have 2 sub-effects: SopsEncryptEffect + FileWriteIO
		if len(compound.Effects) != 2 {
			t.Errorf("Expected 2 sub-effects, got %d", len(compound.Effects))
		}

		// Verify first effect is SopsEncryptEffect
		_, ok = compound.Effects[0].(*framework.SopsEncryptEffect)
		if !ok {
			t.Errorf("Expected first effect to be SopsEncryptEffect, got %T", compound.Effects[0])
		}

		// Verify second effect is FileWriteIO
		_, ok = compound.Effects[1].(*framework.FileWriteIO)
		if !ok {
			t.Errorf("Expected second effect to be FileWriteIO, got %T", compound.Effects[1])
		}

		// Execute the compound effect
		for _, effect := range effects {
			if err := effect.Apply(); err != nil {
				t.Fatalf("Effect execution failed: %v", err)
			}
		}

		// Verify output file was created
		content, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("Failed to read output file: %v", err)
		}

		// Content should be encrypted (not contain original plaintext)
		if bytes.Contains(content, []byte(expectedYaml)) {
			t.Error("Expected encrypted content, but found plaintext")
		}

		// Content should contain SOPS metadata
		if !bytes.Contains(content, []byte("sops:")) {
			t.Errorf("Expected encrypted content to contain SOPS metadata, got: %s", content)
		}

	})

	t.Run("RenderPkl with multiple file output and SOPS encryption", func(t *testing.T) {
		// Check if SOPS is available
		if _, err := exec.LookPath("sops"); err != nil {
			t.Skip("SOPS binary not available, skipping SOPS encryption test")
		}

		params := RenderPklParams{
			PklFile:            testPklFile,
			MultipleFileOutput: true,
			EncryptWithSops:    true,
			EnvVars:            execEnv.EnvVars,
		}

		secrets := koanf.New(".")
		effects, err := RenderPkl(params, secrets)
		if err != nil {
			t.Fatalf("RenderPkl failed: %v", err)
		}

		// Should have 2 CompoundEffects (one for each file)
		if len(effects) != 2 {
			t.Errorf("Expected 2 effects, got %d", len(effects))
		}

		// Execute all effects
		for _, effect := range effects {
			if err := effect.Apply(); err != nil {
				t.Fatalf("Effect execution failed: %v", err)
			}
		}

		// Verify both files were created and encrypted
		for _, filename := range []string{tmpYamlFile1, tmpYamlFile2} {
			content, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", filename, err)
			}

			// Content should be encrypted
			if bytes.Contains(content, []byte(expectedYaml)) {
				t.Errorf("Expected encrypted content in %s, but found plaintext", filename)
			}

			// Content should contain SOPS metadata
			if !bytes.Contains(content, []byte("sops:")) {
				t.Errorf("Expected encrypted content in %s to contain SOPS metadata", filename)
			}

			// value of baz key should be encrypted
			if !bytes.Contains(content, []byte("baz: ENC[AES256")) {
				t.Errorf("Expected value of baz key in %s to be encrypted", filename)
			}

			// value of foo key should be unencrypted
			if !bytes.Contains(content, []byte("foo: bar")) {
				t.Errorf("Expected value of foo key in %s to be unencrypted", filename)
			}
		}
	})
}
