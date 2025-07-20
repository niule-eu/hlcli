package render

import (
	"context"
	"net/url"

	// "log"
	"path"
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
}

func RenderPkl(params RenderPklParams, secrets *koanf.Koanf) (framework.Effect, error) {
	var err error
	oldwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	newwd, err := filepath.Abs(path.Dir(params.PklFile))
	if err != nil {
		return nil, err
	}
	err = os.Chdir(newwd)
	if err != nil {
		return nil, err
	}

	evaluator, err := pkl.NewEvaluator(context.Background(), pkl.PreconfiguredOptions, func(options *pkl.EvaluatorOptions) {
		options.ResourceReaders = append(options.ResourceReaders, SopsResourceReader{secrets: secrets})
		options.AllowedResources = append(options.AllowedResources, "sops")
	})
	if err != nil {
		return nil, err
	}
	defer evaluator.Close()
	os.Chdir(oldwd)

	data, err := evaluator.EvaluateOutputText(context.Background(), pkl.FileSource(params.PklFile))
	if err != nil {
		return nil, err
	}

	return framework.NewDefaultFileWriteIO(params.OutputFile, []byte(data)), nil
}
