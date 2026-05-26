package omnitrail

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/gitoid"
)

type FilePlugin struct {
	algorithms []string
	files      map[string]map[string]string
	AllowList  []string
}

func (plug *FilePlugin) isAllowedDirectory(path string) bool {
	for _, allowedPath := range plug.AllowList {
		if strings.HasPrefix(path, allowedPath) {
			return true
		}
	}
	return false
}

func (plug *FilePlugin) Sha1ADG(m map[string]string) {
	for algo, files := range plug.files {
		if algo == "gitoid:sha1" {
			for _, adg := range files {
				m[adg] = ""
			}
		}
	}
}

func (plug *FilePlugin) Sha256ADG(m map[string]string) {
	for algo, files := range plug.files {
		if algo == "gitoid:sha256" {
			for _, adg := range files {
				m[adg] = ""
			}
		}
	}
}

func (plug *FilePlugin) SetAllowList(allowList []string) {
	plug.AllowList = allowList
}

func NewFilePlugin() Plugin {
	algorithms := []string{"sha1", "sha256", "gitoid:sha1", "gitoid:sha256"}
	sort.Strings(algorithms)
	files := make(map[string]map[string]string)
	for _, algorithms := range algorithms {
		files[algorithms] = make(map[string]string)
	}
	return &FilePlugin{
		algorithms: algorithms,
		files:      files,
	}
}

func (plug *FilePlugin) Add(filePath string) error {

	// ignore broken symlink
	localFileInfo, err := os.Lstat(filePath)
	if err != nil {
		// if it's a symlink and the symlink is bad, ignore and return
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if localFileInfo.Mode()&os.ModeSymlink != 0 {
		targetPath, err := os.Readlink(filePath)
		if err != nil {
			// if it's a symlink and the symlink is bad, ignore and return
			if os.IsNotExist(err) {
				return nil
			}
			fmt.Println("returning err: ", err)
			return err
		}
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(filepath.Dir(filePath), targetPath)
		}
		if !plug.isAllowedDirectory(targetPath) {
			return fmt.Errorf("path %s is not in the allow list", filePath)
		}
		if _, err = os.Stat(targetPath); err != nil {
			return nil
		}
	}
	fileInfo, err := os.Stat(filePath)
	// if file is a symlink and the symlink points to a broken path, return nil
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	// explicitly ignore error from closing file
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	for _, hashAlgo := range plug.algorithms {

		_, err := file.Seek(0, 0)
		if err != nil {
			return err
		}

		if strings.HasPrefix(hashAlgo, "gitoid:") {

			var hashResult *gitoid.GitOID

			switch hashAlgo {
			case "gitoid:sha1":
				hashResult, err = gitoid.New(file, gitoid.WithContentLength(fileInfo.Size()))
			case "gitoid:sha256":
				hashResult, err = gitoid.New(file, gitoid.WithContentLength(fileInfo.Size()), gitoid.WithSha256())
			}

			if err != nil {
				return err
			}

			plug.files[hashAlgo][filePath] = hashResult.String()

		} else {

			switch hashAlgo {
			case "sha1":
				hasher := sha1.New()
				_, err = io.Copy(hasher, file)
				hashBytes := hasher.Sum([]byte{})
				plug.files[hashAlgo][filePath] = fmt.Sprintf("%x", hashBytes)

			case "sha256":
				hasher := sha256.New()
				_, err = io.Copy(hasher, file)
				hashBytes := hasher.Sum([]byte{})
				plug.files[hashAlgo][filePath] = fmt.Sprintf("%x", hashBytes)
			}

		}

	}

	return nil
}

func (plug *FilePlugin) Store(envelope *Envelope) error {
	envelope.Header.Features["file"] = Feature{Algorithms: plug.algorithms}
	for algorithm, paths := range plug.files {
		for path, hash := range paths {
			if _, ok := envelope.Mapping[path]; !ok {
				envelope.Mapping[path] = &Element{
					Type: fmt.Sprintf("%s", "file"),
				}
			}
			{
				e := envelope.Mapping[path]
				switch algorithm {
				case "sha1":
					e.Sha1 = hash
				case "sha256":
					e.Sha256 = hash
				case "gitoid:sha1":
					e.Sha1Gitoid = hash
				case "gitoid:sha256":
					e.Sha256Gitoid = hash
				}
				envelope.Mapping[path] = e
			}
		}
	}
	return nil
}
