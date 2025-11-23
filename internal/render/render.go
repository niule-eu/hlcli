package render

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"

	// "log"

	"path/filepath"
	"strings"

	// "fmt"
	"os"

	"github.com/apple/pkl-go/pkl"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/v2"
	"github.com/niule-eu/hlcli/pkg/framework"
)

var (
	parser = yaml.Parser()
)

type PklProjectNotFoundError struct {
	Module string
}

func (e *PklProjectNotFoundError) Error() string {
	return fmt.Sprintf("No PklProject found for module '%s'", e.Module)
}

type MultiplePklProjectFoundError struct {
	Module          string
	PklProjectFiles []string
}

func (e *MultiplePklProjectFoundError) Error() string {
	return fmt.Sprintf(
		"More than 1 PklProject found for module '%s':\n%s",
		e.Module,
		strings.Join(e.PklProjectFiles, "\n"),
	)
}

type SopsBlobResourceReader struct{}

func (r SopsBlobResourceReader) Scheme() string { return "sopsblob" }

func (r SopsBlobResourceReader) IsGlobbable() bool { return false }

func (r SopsBlobResourceReader) HasHierarchicalUris() bool { return false }

func (r SopsBlobResourceReader) ListElements(url url.URL) ([]pkl.PathElement, error) { return nil, nil }

func (r SopsBlobResourceReader) Read(url url.URL) ([]byte, error) {

	p := url.Path
	secretsBytes, err := decrypt.File(p, "binary")
	if err != nil {
		return nil, err
	}

	return secretsBytes, nil
}

type SopsResourceReader struct {
	secrets *koanf.Koanf
}

func (r SopsResourceReader) Scheme() string { return "sops" }

func (r SopsResourceReader) IsGlobbable() bool { return false }

func (r SopsResourceReader) HasHierarchicalUris() bool { return false }

func (r SopsResourceReader) ListElements(url url.URL) ([]pkl.PathElement, error) { return nil, nil }

func (r SopsResourceReader) Read(url url.URL) ([]byte, error) {

	key := strings.Replace(url.Path[1:], "/", ".", -1)
	subMap := r.secrets.Cut(key)

	if len(subMap.Keys()) > 0 {
		return subMap.Marshal(parser)
	} else {
		return []byte(r.secrets.String(key)), nil
	}
}

type SopsTarResourceReader struct{}

func (r SopsTarResourceReader) Scheme() string { return "sopstar" }

func (r SopsTarResourceReader) IsGlobbable() bool { return false }

func (r SopsTarResourceReader) HasHierarchicalUris() bool { return true }

func (r SopsTarResourceReader) ListElements(url url.URL) ([]pkl.PathElement, error) { return nil, nil }

func (r SopsTarResourceReader) Read(url url.URL) ([]byte, error) {

	p := url.Path
	fragment := url.Fragment

	secretsBytes, err := decrypt.File(p, "binary")
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(secretsBytes)
	tr := tar.NewReader(buf)
	fileBytes := &bytes.Buffer{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == fragment {
			_, err := io.Copy(fileBytes, tr)
			if err != nil {
				return nil, err
			}
			return fileBytes.Bytes(), nil
		}
	}
	return secretsBytes, nil
}

type RenderPklParams struct {
	PklFile        string
	OutputFile     string
	Expression     string
	AllowedModules []string
	PklProjectFile string
}

func RenderPkl(params RenderPklParams, secrets *koanf.Koanf) (framework.Effect, error) {
	var err error
	var evaluator_err error
	var evaluator pkl.Evaluator

	evaluatorManager := pkl.NewEvaluatorManager()

	pkl_project_root, err := findPklProjectRoot(params.PklFile, params.PklProjectFile)
	if _, ok := err.(*PklProjectNotFoundError); ok {
		evaluator, evaluator_err = evaluatorManager.NewEvaluator(
			context.Background(),
			pkl.PreconfiguredOptions,
			evaluatorOptions(secrets),
		)
		if evaluator_err != nil {
			return nil, evaluator_err
		}
	} else if err == nil {
		evaluator, evaluator_err = evaluatorManager.NewProjectEvaluator(
			context.Background(),
			&url.URL{
				Scheme: "file",
				Path:   pkl_project_root,
			},
			pkl.PreconfiguredOptions,
			evaluatorOptions(secrets),
		)
		if evaluator_err != nil {
			return nil, evaluator_err
		}
	} else {
		return nil, err
	}
	defer evaluator.Close()

	var data []byte
	var out string
	// Check if expression provided, if yes evaluate expression and write to file
	if params.Expression != "" {
		data, err = evaluator.EvaluateExpressionRaw(context.Background(), pkl.FileSource(params.PklFile), params.Expression)
		if err != nil {
			return nil, err
		}
		pkl.Unmarshal(data, data)
	} else {
		data, err = evaluator.EvaluateExpressionRaw(context.Background(), pkl.FileSource(params.PklFile), "output.text")
		if err != nil {
			return nil, err
		}
	}
	err = pkl.Unmarshal(data, &out)
	if err != nil {
		return nil, err
	}
	return framework.NewDefaultFileWriteIO(params.OutputFile, []byte(out)), nil
}

func evaluatorOptions(secrets *koanf.Koanf) func(*pkl.EvaluatorOptions) {
	return func(options *pkl.EvaluatorOptions) {
		options.ResourceReaders = append(options.ResourceReaders, SopsResourceReader{secrets: secrets})
		options.ResourceReaders = append(options.ResourceReaders, SopsBlobResourceReader{})
		options.ResourceReaders = append(options.ResourceReaders, SopsTarResourceReader{})
		options.AllowedResources = append(options.AllowedResources, "sops")
		options.AllowedResources = append(options.AllowedResources, "sopsblob")
		options.AllowedResources = append(options.AllowedResources, "sopstar")
	}
}

func findPklProjectRoot(mod_path string, project_path string) (string, error) {
	// If project_path provided, check if it exists and if it does, return it
	if project_path != "" {
		if _, err := os.Stat(project_path); err == nil {
			return project_path, nil
		}
	}

	// project_path does not exist or not povided, search for it along mod_path
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	pkl_project_file_paths := []string{}
	filepath.WalkDir(wd, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			afterCut, isPrefix := strings.CutPrefix(mod_path, path)
			if !(isPrefix && strings.HasPrefix(afterCut, "/")) {
				return filepath.SkipDir
			}
		} else if d.Name() == "PklProject" {
			pkl_project_file_paths = append(pkl_project_file_paths, filepath.Dir(path))
		}
		return nil
	})
	if len(pkl_project_file_paths) == 1 {
		return pkl_project_file_paths[0], nil
	} else if len(pkl_project_file_paths) == 0 {
		return "", &PklProjectNotFoundError{
			Module: mod_path,
		}
	} else {
		return "", &MultiplePklProjectFoundError{
			Module:          mod_path,
			PklProjectFiles: pkl_project_file_paths,
		}
	}
}
