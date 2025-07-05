package main

import (
	"context"
	"fmt"
	"path"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"log"
	"os"
	"os/exec"

	"github.com/niuleh/hlcli/internal/config"
	"github.com/niuleh/hlcli/internal/framework"
	"github.com/niuleh/hlcli/internal/keygen"
	"github.com/niuleh/hlcli/internal/netconf"
	"github.com/niuleh/hlcli/internal/render"

	"github.com/adrg/xdg"
	"github.com/knadh/koanf/v2"
	"github.com/urfave/cli/v3"

	"github.com/apple/pkl-go/pkl"
)

type CommandConfig struct {
	Secrets string `yaml:"secrets,omitempty"`
}

type DefaultConfig struct {
	Commands map[string]CommandConfig `yaml:"commands"`
}

func debugConfig(cfg *koanf.Koanf) *cli.Command {
	return &cli.Command{
		Name: "debug_cfg",
		Action: func(ctx context.Context, c *cli.Command) error {
			for k, v := range cfg.All() {
				fmt.Println(k, "value is", v)
			}
			return nil
		},
	}
}

func renderPklCommand(secrets *koanf.Koanf) *cli.Command {
	return &cli.Command{
		Name: "render-pkl",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "module",
				Aliases:  []string{"m"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "/dev/stdout",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			var module = c.String("module")
			if !path.IsAbs(module) {
				var err error
				module, err = filepath.Abs(module)
				if err != nil {
					return err
				}
			}
			effect, err :=
				render.RenderPkl(
					render.RenderPklParams{
						PklFile:    module,
						OutputFile: c.String("output"),
					},
					secrets,
				)
			if err != nil {
				log.Fatal(err)
			}
			framework.Invoke(effect)
			if err != nil {
				log.Fatal(err)
			}
			return nil
		},
	}
}

func keygen_cmd() *cli.Command {
	return &cli.Command{
		Name: "keygen",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "/dev/stdout",
			},
			&cli.StringFlag{
				Name:     "comment",
				Aliases:  []string{"c"},
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "replace",
				Aliases: []string{"r"},
				Value:   false,
			},
		},
		// TODO: check if file exists before running the subcommands
		// Before: func(ctx context.Context, c *cli.Command) error {
		// }
		Commands: []*cli.Command{
			{
				Name: "rsa",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "bits",
						Aliases:  []string{"b"},
						Required: true,
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					effect, err :=
						keygen.RSAKeyGen{
							Bits:    int(c.Int("bits")),
							Comment: c.String("comment"),
							Output:  c.String("output"),
						}.Prepare()
					framework.Invoke(effect...)
					if err != nil {
						log.Fatal(err)
					}
					return nil
				},
			},
			{
				Name: "ecdsa",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "bits",
						Aliases:  []string{"b"},
						Required: true,
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					effect, err :=
						keygen.ECDSAKeyGen{
							CurveBits: int(c.Int("bits")),
							Comment:   c.String("comment"),
							Output:    c.String("output"),
						}.Prepare()
					framework.Invoke(effect...)
					if err != nil {
						log.Fatal(err)
					}
					return nil
				},
			},
			{
				Name: "ed25519",
				Action: func(ctx context.Context, c *cli.Command) error {
					effect, err :=
						keygen.ED25519KeyGen{
							Comment: c.String("comment"),
							Output:  c.String("output"),
						}.Prepare()
					framework.Invoke(effect...)
					if err != nil {
						log.Fatal(err)
					}
					return nil

				},
			},
		},
	}
}

func netconf_cmd() *cli.Command {
	return &cli.Command{
		Name: "netconf",
		Commands: []*cli.Command{
			{
				Name: "get-config",
				Action: func(ctx context.Context, c *cli.Command) error {
					netconf.Example_ssh()
					return nil
				},
			},
		},
	}
}

func no_config() error {
	p, err := xdg.ConfigFile("hlcli/config.yaml")
	if err != nil {
		return err
	}
	_file, err := os.Create(p)
	if err != nil {
		return err
	}
	defaultConfig, err := yaml.Marshal(DefaultConfig{Commands: map[string]CommandConfig{"root": CommandConfig{}}})
	if err != nil {
		return err
	}
	_, err = _file.Write(defaultConfig)
	if err != nil {
		return err
	}
	return nil

}

func get_default_config_path() string {
	p, err := xdg.SearchConfigFile("hlcli/config.yaml")
	if err != nil {
		err = no_config()
		if err != nil {
			log.Fatal(err)
		}
		return get_default_config_path()
	}
	return p
}

func load_config(cliConfig *koanf.Koanf, sopsSecrets *koanf.Koanf) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		var cliConfigPath string
		var err error
		cliConfigPath, err = filepath.Abs(cmd.String("config"))
		if err != nil {
			log.Fatal(err)
		}
		err = config.LoadConfig(config.NewDefaultLoadConfigParams(), cliConfig, func(lcp *config.LoadConfigParams) {
			lcp.CliConfigPaths = append(lcp.CliConfigPaths, cliConfigPath)
		})
		if err != nil {
			log.Fatal(err)
		}

		if exists := cliConfig.Exists("commands.root.secrets"); exists {
			p, err := filepath.Abs(cliConfig.String("commands.root.secrets"))
			if err != nil {
				log.Fatal(err)
			}
			err = config.LoadSecrets(config.NewDefaultLoadSecretsParams(), sopsSecrets, func(lsp *config.LoadSecretsParams) {
				lsp.SecretsPaths = append(lsp.SecretsPaths, p)
			})
			if err != nil {
				log.Fatal(err)
			}
		}

		return nil, nil
	}
}

func main() {
	koanfConf := koanf.Conf{
		Delim:       ".",
		StrictMerge: true,
	}
	cliConfig := koanf.NewWithConf(koanfConf)
	sopsSecrets := koanf.NewWithConf(koanfConf)

	app := &cli.Command{
		Name:  "hlcli",
		Usage: "infrastructure as command line interface",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Value:   get_default_config_path(),
				Aliases: []string{"c"},
				Usage:   "Load configuration from `FILE`",
			},
		},
		Before: load_config(cliConfig, sopsSecrets),
		Commands: []*cli.Command{
			debugConfig(cliConfig),
			keygen_cmd(),
			netconf_cmd(),
			renderPklCommand(sopsSecrets),
			{
				Name:            "tofu",
				Aliases:         []string{"tf"},
				SkipFlagParsing: true,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					args := cmd.Args().Slice()
					if len(args) == 0 {
						args = []string{"-version"}
					}
					exe := exec.Command("tofu", args...)
					exeEnv, err := config.SecretsToEnv(sopsSecrets, "TF_VAR")
					if err != nil {
						log.Fatal(err)
					}
					exe.Env = exeEnv
					exe.Stdout = os.Stdout
					exe.Stderr = os.Stderr
					pkl.NewEvaluator(context.Background(), pkl.PreconfiguredOptions)
					if err := exe.Run(); err != nil {
						log.Fatal("tofu command failed with:", err)
					}
					return nil
				},
			},
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
