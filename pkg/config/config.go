package config

import (
	"fmt"
	"strings"

	"github.com/getsops/sops/v3/decrypt"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
)

type LoadConfigParams struct {
	Cfg             *koanf.Conf
	EnvVarsPrefixes []string
	CliConfigPaths  []string
}

type LoadSecretsParams struct {
	Cfg          *koanf.Conf
	SecretsPaths []string
}

func NewDefaultLoadConfigParams() *LoadConfigParams {
	return &LoadConfigParams{
		Cfg: &koanf.Conf{
			Delim:       ".",
			StrictMerge: true,
		},
		EnvVarsPrefixes: []string{"HLCLI"},
		CliConfigPaths:  []string{},
	}
}

func NewDefaultLoadSecretsParams() *LoadSecretsParams {
	return &LoadSecretsParams{
		Cfg: &koanf.Conf{
			Delim:       ".",
			StrictMerge: true,
		},
		SecretsPaths: []string{},
	}
}

func LoadConfig(cfg *LoadConfigParams, final *koanf.Koanf, opts ...func(*LoadConfigParams)) error {
	for _, f := range opts {
		f(cfg)
	}

	fromEnv := koanf.NewWithConf(*cfg.Cfg)
	for _, prefix := range cfg.EnvVarsPrefixes {
		tmp := koanf.NewWithConf(*cfg.Cfg)
		err := tmp.Load(env.Provider(prefix, ".", func(s string) string {
			return strings.Replace(strings.ToLower(strings.TrimPrefix(s, prefix+"_")), "_", ".", -1)
		}), nil)
		if err != nil {
			return err
		}
		fromEnv.Merge(tmp)
	}

	fromFile := koanf.NewWithConf(*cfg.Cfg)
	for _, p := range cfg.CliConfigPaths {
		tmp := koanf.NewWithConf(*cfg.Cfg)
		err := fromFile.Load(file.Provider(p), yaml.Parser())
		if err != nil {
			return err
		}
		fromFile.Merge(tmp)
	}
	final.Merge(fromFile)
	final.Merge(fromEnv)

	return nil
}

func LoadSecrets(cfg *LoadSecretsParams, secrets *koanf.Koanf, opts ...func(*LoadSecretsParams)) error {
	for _, f := range opts {
		f(cfg)
	}

	fromSops := koanf.NewWithConf(*cfg.Cfg)
	for _, p := range cfg.SecretsPaths {
		secretsBytes, err := decrypt.File(p, "yaml")
		if err != nil {
			return err
		}
		tmp := koanf.NewWithConf(*cfg.Cfg)
		err = tmp.Load(rawbytes.Provider(secretsBytes), yaml.Parser())
		if err != nil {
			return err
		}
		fromSops.Merge(tmp)
	}

	secrets.Merge(fromSops)

	return nil
}

func SecretsToEnv(secrets *koanf.Koanf, prefix ...string) ([]string, error) {
	out := []string{}
	for _, key := range secrets.Keys() {
		envVar := strings.ToUpper(strings.ReplaceAll(strings.Join(append(prefix, key), "_"), ".", "_"))
		out = append(out, fmt.Sprint(envVar, "=", secrets.String(key)))
	}
	return out, nil
}
