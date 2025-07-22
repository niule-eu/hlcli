package hlcli_cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/niule-eu/hlcli/pkg/framework"
	"github.com/niule-eu/hlcli/pkg/ghasset"

	"github.com/knadh/koanf/v2"
	"github.com/urfave/cli/v3"
	"go.yaml.in/yaml/v3"
)

func writeAsset(path string, assets ...*ghasset.ReleaseAssetResult) (framework.Effect, error) {
	var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
	var b strings.Builder
	for _, asset := range assets {
		prefix := nonAlphanumericRegex.ReplaceAllString(
			strings.ToUpper(fmt.Sprintf("%s_%s_", asset.Owner, asset.Repo)), "_",
		)
		parts := []string{prefix, "TAG=", asset.Tag, "\n", prefix, "URL=", asset.Url, "\n"}
		if asset.Hash != nil {
			parts = append(parts, prefix, "HASH=", asset.Hash.Value,  "\n")
		}
		for _, part := range parts {
			_, err := b.WriteString(part)
			if err != nil {
				return nil, err
			}
		}
	}
	res := framework.NewDefaultFileWriteIO(path, []byte(b.String()))
	return res, nil
}

func GhAssetCmd(secrets *koanf.Koanf) *cli.Command {
	return  &cli.Command{
		Name: "gh-asset",
		Flags: []cli.Flag{
			&cli.StringFlag { Name: "token-ref", Aliases: []string{"tref", "tr"}, Required: true, },
		},
		Commands: []*cli.Command{
			{
				Name: "get-one",
				Flags: []cli.Flag {
					&cli.StringFlag { Name: "owner", Required: true, },
					&cli.StringFlag { Name: "repo", Required: true, },
					&cli.StringFlag { Name: "pattern", Required: true, },
					&cli.StringFlag { Name: "checksums-pattern", Required: false, },
					&cli.StringFlag { Name: "prefix", Value: "", },
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					checksumsPattern := c.String("checksums-pattern")
					res, err := ghasset.GetAsset(
						secrets.String(c.String("token-ref")), 
						ghasset.ReleaseAssetQuery {
							Owner: c.String("owner"),
							Repo: c.String("repo"),
							Pattern: c.String("pattern"),
							ChecksumsPattern: &checksumsPattern,
					})
					if err != nil {
						return err
					}
					log.Println(res)
					return nil
				},
			},
			{
				Name: "get-many",
				Flags: []cli.Flag {
					&cli.StringFlag { Name: "queries-file", Aliases: []string{"q"}, Required: true},
					&cli.StringFlag { Name: "dotenv-output-file", Aliases: []string{"o"}, Value: "/dev/stdout"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					queriesRaw, err := os.ReadFile(c.String("queries-file"))
					if err != nil {
						return err
					}
					var queries []ghasset.ReleaseAssetQuery
					yaml.Unmarshal(queriesRaw, &queries)
					res := make([]*ghasset.ReleaseAssetResult, len(queries))
					for i, q := range queries {
						a, err := ghasset.GetAsset(
							secrets.String(c.String("token-ref")),
							ghasset.ReleaseAssetQuery{
								Owner: q.Owner,
								Repo: q.Repo,
								Pattern: q.Pattern,
								ChecksumsPattern: q.ChecksumsPattern,
							},
						)
						if err != nil {
							return nil
						}
						res[i] = a
					}
					eff, err := writeAsset(c.String("dotenv-output-file"), res...)
					if err != nil {
						return err
					}
					return eff.Apply()
				},
			},
		},
	}
}