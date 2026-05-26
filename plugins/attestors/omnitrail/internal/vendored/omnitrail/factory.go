package omnitrail

import (
	"io/fs"
	"path/filepath"
	"sort"
)

type factoryImpl struct {
	Options   *Options
	envelope  *Envelope
	Plugins   []Plugin
	AllowList []string
}

func (factory *factoryImpl) Add(originalPath string) error {
	// Convert the path to an absolute path
	absPath, err := filepath.Abs(originalPath)
	if err != nil {
		return err
	}

	// Add the absolute path to the allow list
	factory.AllowList = append(factory.AllowList, absPath)

	// For each plugin, add the allow list
	for _, plugin := range factory.Plugins {
		plugin.SetAllowList(factory.AllowList)
	}

	// check if path already exists in the envelope, if so, return
	if _, ok := factory.envelope.Mapping[originalPath]; ok {
		return nil
	}
	err = filepath.WalkDir(originalPath, func(path string, d fs.DirEntry, err error) error {
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		for _, plugin := range factory.Plugins {
			err := plugin.Add(path)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Generate ADGs for directories
	// collect all keys in the map
	var keys []string
	for k := range factory.envelope.Mapping {
		keys = append(keys, k)
	}
	// sort keys by lexical order
	sort.Strings(keys)

	// stable sort keys by length
	sort.SliceStable(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	for _, plugin := range factory.Plugins {
		err := plugin.Store(factory.envelope)
		if err != nil {
			return err
		}
	}

	return nil
}

func (factory *factoryImpl) Sha1ADGs() map[string]string {
	m := make(map[string]string)
	for _, plugin := range factory.Plugins {
		plugin.Sha1ADG(m)
	}
	return m
}

// Sha256ADGs return sha256 omnibor objects
func (factory *factoryImpl) Sha256ADGs() map[string]string {
	m := make(map[string]string)
	for _, plugin := range factory.Plugins {
		plugin.Sha256ADG(m)
	}
	return m
}

func (factory *factoryImpl) Envelope() *Envelope {
	return factory.envelope
}
