package render

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/url"

	// "log"

	"path/filepath"
	"strings"

	// "fmt"
	"os"

	"github.com/apple/pkl-go/pkl"
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

type RenderPklParams struct {
	PklFile        string
	OutputFile     string
	AllowedModules []string
	PklProjectFile string
}

func RenderPkl(params RenderPklParams, secrets *koanf.Koanf) (framework.Effect, error) {
	var err error

	pkl_project_root, err := findPklProjectRoot(params.PklFile, params.PklProjectFile)
	if err != nil {
		return nil, err
	}

	evaluatorManager := pkl.NewEvaluatorManager()
	evaluator, err := evaluatorManager.NewProjectEvaluator(
		context.Background(),
		pkl_project_root,
		pkl.PreconfiguredOptions,
		func(options *pkl.EvaluatorOptions) {
			options.ResourceReaders = append(options.ResourceReaders, SopsResourceReader{secrets: secrets})
			options.AllowedResources = append(options.AllowedResources, "sops")
		},
	)
	if err != nil {
		return nil, err
	}
	defer evaluator.Close()

	data, err := evaluator.EvaluateOutputText(context.Background(), pkl.FileSource(params.PklFile))
	if err != nil {
		return nil, err
	}

	return framework.NewDefaultFileWriteIO(params.OutputFile, []byte(data)), nil
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
			if !strings.HasPrefix(mod_path, path) {
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
