// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package agentplugin carries the customer-facing Pushgate agent skill and
// installs it where coding agents discover skills.
//
// The skill's single source of truth is the directory next to this file,
// pushgate/, laid out as a Claude Code plugin. The rookery repository's
// marketplace (.claude-plugin/marketplace.json at the rookery root) points at
// that same directory, and this package embeds it, so the marketplace copy and
// the copy inside a cilock binary are the same bytes by construction. The
// skill therefore versions with cilock: `cilock skill show` prints the copy
// that matches the binary.
package agentplugin

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// SkillName is the skill's name: its directory name and its frontmatter name.
// opencode requires the two to match (^[a-z0-9]+(-[a-z0-9]+)*$).
const SkillName = "pushgate"

// PluginDir is the plugin directory, relative to this package. SkillDir is
// the skill inside it, laid out as Claude Code's plugin format requires
// (<plugin>/skills/<name>/SKILL.md).
const (
	PluginDir = "pushgate"
	SkillDir  = PluginDir + "/skills/" + SkillName
)

// The embed names the skill directory, not a glob of known files, so a new
// reference file is picked up without touching this line. Dot and underscore
// files are excluded by go:embed's directory rule; the skill has none.
//
//go:embed pushgate/skills/pushgate
var skillFS embed.FS

// File is one file of the skill, with its path relative to the skill
// directory (for example "SKILL.md" or "references/refusals.md").
type File struct {
	Path string
	Data []byte
}

// Files returns every file of the embedded skill, sorted by path.
func Files() ([]File, error) {
	var files []File
	err := fs.WalkDir(skillFS, SkillDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := skillFS.ReadFile(p)
		if err != nil {
			return err
		}
		rel := p[len(SkillDir)+1:]
		if !fs.ValidPath(rel) || path.IsAbs(rel) {
			return fmt.Errorf("embedded skill file %q has an invalid path", p)
		}
		files = append(files, File{Path: rel, Data: data})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read embedded skill: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// ReadFile returns one embedded skill file by its path relative to the skill
// directory.
func ReadFile(rel string) ([]byte, error) {
	if !fs.ValidPath(rel) {
		return nil, fmt.Errorf("invalid skill file path %q", rel)
	}
	return skillFS.ReadFile(SkillDir + "/" + rel)
}

// SkillMarkdown returns the embedded SKILL.md.
func SkillMarkdown() []byte {
	data, err := ReadFile("SKILL.md")
	if err != nil {
		// The embed directive guarantees the file at build time; a binary
		// without it could not have compiled.
		panic(err)
	}
	return data
}
