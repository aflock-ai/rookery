// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// cilockConfig is the parsed shape of a .cilock.yaml / .witness.yaml file.
// The outer map is keyed by cobra command name; the inner map is keyed by
// flag name. Values are raw YAML scalars/sequences/mappings preserved as
// any so that getStringFromConfig / getStringSliceFromConfig can coerce
// them with the same semantics viper used to apply.
type cilockConfig map[string]map[string]any

// loadCilockConfig reads and parses a cilock/witness config file. The file
// format is YAML with a top-level mapping of command name -> (flag name ->
// value). Returns an empty config if path does not exist; the caller is
// responsible for deciding whether a missing file is a fatal error.
func loadCilockConfig(path string) (cilockConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-supplied via --config flag
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse into a generic map so we can preserve native types
	// (string, bool, int, []any) the same way viper did.
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := make(cilockConfig, len(raw))
	for cmdName, sub := range raw {
		inner, ok := sub.(map[string]any)
		if !ok {
			// Top-level scalar / non-mapping under a command name has no
			// flags to apply; skip it silently to match viper's behavior
			// of returning empty string / empty slice for unknown keys.
			continue
		}
		cfg[cmdName] = inner
	}
	return cfg, nil
}

// getStringFromConfig returns the value for cmdName.flagName as a string,
// matching viper.GetString's coercion: bool -> "true"/"false",
// numbers -> decimal string, string -> string, others -> "" if absent.
func getStringFromConfig(cfg cilockConfig, cmdName, flagName string) string {
	cmdCfg, ok := cfg[cmdName]
	if !ok {
		return ""
	}
	v, ok := cmdCfg[flagName]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// getStringSliceFromConfig returns the value for cmdName.flagName as a
// slice of strings, matching viper.GetStringSlice's behavior: a YAML
// sequence becomes []string with each element coerced; a single scalar
// becomes a one-element slice; absent / nil becomes nil.
func getStringSliceFromConfig(cfg cilockConfig, cmdName, flagName string) []string {
	cmdCfg, ok := cfg[cmdName]
	if !ok {
		return nil
	}
	v, ok := cmdCfg[flagName]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, coerceScalarString(item))
		}
		return out
	case []string:
		return t
	default:
		// Single scalar in a slice flag -> one-element slice, matching
		// viper's GetStringSlice on a non-sequence value.
		return []string{coerceScalarString(v)}
	}
}

func coerceScalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func initConfig(rootCmd *cobra.Command, rootOptions *options.RootOptions) error {
	if _, err := os.Stat(rootOptions.Config); errors.Is(err, os.ErrNotExist) {
		if rootCmd.Flags().Lookup("config").Changed {
			return fmt.Errorf("config file %s does not exist", rootOptions.Config)
		}
		log.Debugf("%s does not exist, using command line arguments", rootOptions.Config)
		return nil
	}

	log.Infof("Using config file: %v", rootOptions.Config)

	cfg, err := loadCilockConfig(rootOptions.Config)
	if err != nil {
		return err
	}

	for _, cm := range rootCmd.Commands() {
		if !contains(os.Args, cm.Name()) {
			continue
		}
		if err := applyConfigToCommand(cm, cfg); err != nil {
			return err
		}
	}
	return nil
}

// applyConfigToCommand walks the command's flags and sets any not already
// supplied on the CLI from the loaded config map.
func applyConfigToCommand(cm *cobra.Command, cfg cilockConfig) error {
	var configErr error
	cm.Flags().VisitAll(func(f *pflag.Flag) {
		if configErr != nil || f.Changed {
			return
		}
		if err := applyConfigValue(cm, cfg, f); err != nil {
			configErr = err
		}
	})
	return configErr
}

// applyConfigValue resolves the config value for one flag and sets it on the
// command, returning a wrapped error if pflag rejects the value.
func applyConfigValue(cm *cobra.Command, cfg cilockConfig, f *pflag.Flag) error {
	flags := cm.Flags()
	if f.Value.Type() == "stringSlice" {
		v := getStringSliceFromConfig(cfg, cm.Name(), f.Name)
		if len(v) == 0 {
			return nil
		}
		if err := flags.Set(f.Name, strings.Join(v, ",")); err != nil {
			return fmt.Errorf("failed to set config value %q from config file: %w", cm.Name()+"."+f.Name, err)
		}
		return nil
	}
	v := getStringFromConfig(cfg, cm.Name(), f.Name)
	if v == "" {
		return nil
	}
	if err := flags.Set(f.Name, v); err != nil {
		return fmt.Errorf("failed to set config value %q from config file: %w", cm.Name()+"."+f.Name, err)
	}
	return nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
