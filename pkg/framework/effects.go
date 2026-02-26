package framework

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"

	sopsConfig "github.com/getsops/sops/v3/config"
)

type Effect interface {
	Apply() error
}

type FileWriteIO struct {
	Path        string
	Content     *[]byte
	Mode        int
	Permissions os.FileMode
}

func NewDefaultFileWriteIO(path string, content *[]byte) *FileWriteIO {
	return &FileWriteIO{
		Path:        path,
		Content:     content,
		Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		Permissions: 0644,
	}
}

func NewFileWriteIOWithRef(path string, content *[]byte) *FileWriteIO {
	return &FileWriteIO{
		Path:        path,
		Content:     content,
		Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		Permissions: 0644,
	}
}

func (fw FileWriteIO) Apply() error {
	f, err := os.OpenFile(fw.Path, fw.Mode, fw.Permissions)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bufio.NewWriter(f)
	_, err = buf.Write(*fw.Content)
	if err != nil {
		return err
	}

	f.Sync()
	buf.Flush()
	return nil
}

type FileDeleteIO struct {
	Path string
	Op   func(string) error
}

func (fdio *FileDeleteIO) Apply() error {
	return fdio.Op(fdio.Path)
}

type NoOp struct{}

func (n *NoOp) Apply() error {
	return nil
}

type StdOutIO struct {
	Message string
}

func (sdtoutio *StdOutIO) Apply() error {
	log.Println(sdtoutio.Message)
	return nil
}

func NewStdOutIO(msg string) *StdOutIO {
	return &StdOutIO{
		Message: msg,
	}
}

type CompoundEffect struct {
	Effects []Effect
}

func (fw CompoundEffect) Apply() error {
	var errs []error
	for _, e := range fw.Effects {
		if err := e.Apply(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SopsEncryptEffect encrypts content using the SOPS binary
// It takes a reference to a byte slice containing plaintext and replaces it
// with the encrypted ciphertext in-place. The effect handles:
// 1. Checking SOPS binary availability
// 2. Executing SOPS encryption subprocess
// 3. Piping plaintext to SOPS via stdin
// 4. Capturing encrypted output from SOPS stdout
// 5. Replacing plaintext with ciphertext in the byte slice
// 6. Error handling and cleanup
// Note: This effect ONLY handles in-memory encryption. File writing is handled
// separately by FileWriteIO to maintain separation of concerns.
type SopsEncryptEffect struct {
	Plaintext        *[]byte           // Reference to plaintext content in memory
	ConfigPath       string            // Optional path to SOPS configuration file
	FilenameOverride string            // Filename override for SOPS (required when using stdin)
	EnvVars          map[string]string // Environment variables to set for SOPS execution
}

// NewSopsEncryptEffect creates a new SopsEncryptEffect with default values
// Uses "encrypted.json" as the default filename override
func NewDefaultSopsEncryptEffect(plaintext *[]byte) *SopsEncryptEffect {
	return &SopsEncryptEffect{
		Plaintext:        plaintext,
		ConfigPath:       "",
		FilenameOverride: "encrypted.json", // Default filename override
		EnvVars:          nil,
	}
}

// NewSopsEncryptEffect creates a new SopsEncryptEffect with all fields specified
// This constructor requires explicit values for all configuration options
func NewSopsEncryptEffect(plaintext *[]byte, configPath string, filenameOverride string, envVars map[string]string) *SopsEncryptEffect {
	return &SopsEncryptEffect{
		Plaintext:        plaintext,
		ConfigPath:       configPath,
		FilenameOverride: filenameOverride,
		EnvVars:          envVars,
	}
}

// Apply encrypts the plaintext content using the SOPS binary.
// It pipes the plaintext to SOPS via stdin and captures the encrypted output from stdout,
// replacing the original plaintext with ciphertext in-place.
// If SOPS binary is not found or encryption fails, the original content is preserved.
func (e *SopsEncryptEffect) Apply() error {
	// Check if SOPS binary is available
	if _, err := exec.LookPath("sops"); err != nil {
		return fmt.Errorf("sops binary not found in PATH: %w", err)
	}

	// Build SOPS command - use 'encrypt' as subcommand
	args := []string{}
	if e.ConfigPath != "" {
		args = append(args, "--config", e.ConfigPath)
	} else {
		discoveredConfig, err := sopsConfig.FindConfigFile(".")
		if err == nil {
			args = append(args, "--config", discoveredConfig)
		}
	}
	args = append(args, "encrypt", "--filename-override", e.FilenameOverride)

	cmd := exec.Command("sops", args...)

	// Set up stdin with plaintext
	cmd.Stdin = bytes.NewReader(*e.Plaintext)

	// Set environment variables if provided
	if e.EnvVars != nil {
		cmd.Env = os.Environ()
		for key, value := range e.EnvVars {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("No working directory found, unknown execution environment")
	}
	cmd.Dir = cwd
	// Capture stdout for encrypted output
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Execute SOPS encryption
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops encryption failed: %w (stderr: %s)", err, stderrBuf.String())
	}

	*e.Plaintext = stdoutBuf.Bytes()

	return nil
}

func Invoke(effect ...Effect) error {
	var errs []error
	for _, e := range effect {
		if err := e.Apply(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}
