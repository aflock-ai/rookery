package omnitrail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type PosixPlugin struct {
	params    map[string]*posixInfo
	AllowList []string
}

func (p *PosixPlugin) isAllowedDirectory(path string) bool {
	for _, allowedPath := range p.AllowList {
		if strings.HasPrefix(path, allowedPath) {
			return true
		}
	}
	return false
}

type posixInfo struct {
	permMode os.FileMode
	uid      uint32
	gid      uint32
	size     int64
}

func (p *PosixPlugin) Add(path string) error {

	// check if symlink is broken
	localFileInfo, err := os.Lstat(path)
	if err != nil {
		// if it's a symlink and the symlink is bad, ignore and return
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if localFileInfo.Mode()&os.ModeSymlink != 0 {
		targetPath, err := os.Readlink(path)
		if err != nil {
			// if it's a symlink and the symlink is bad, ignore and return
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(filepath.Dir(path), targetPath)
		}
		if !p.isAllowedDirectory(targetPath) {
			return fmt.Errorf("path %s is not in the allow list", path)
		}
		if _, err = os.Stat(targetPath); err != nil {
			return nil
		}
	}
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	perms := stat.Mode()

	if _, ok := p.params[path]; !ok {
		p.params[path] = &posixInfo{}
	}
	p.params[path].permMode = perms
	statt := stat.Sys().(*syscall.Stat_t)
	p.params[path].uid = statt.Uid
	p.params[path].gid = statt.Gid
	// if path is a directory, set size to 0
	if !perms.IsDir() {
		p.params[path].size = stat.Size()
	}
	return nil
}

func (p *PosixPlugin) Store(envelope *Envelope) error {
	envelope.Header.Features["posix"] = Feature{}
	for path, element := range envelope.Mapping {
		if element.Posix == nil {
			element.Posix = &Posix{}
		}
		element.Posix.Permissions = p.params[path].permMode.String()
		element.Posix.OwnerUID = strconv.Itoa(int(p.params[path].uid))
		element.Posix.OwnerGID = strconv.Itoa(int(p.params[path].gid))
		if p.params[path].size != 0 {
			element.Posix.Size = strconv.Itoa(int(p.params[path].size))
		}
	}
	return nil
}

func (p *PosixPlugin) Sha1ADG(_ map[string]string) {
}

func (p *PosixPlugin) Sha256ADG(_ map[string]string) {
}

func (plug *PosixPlugin) SetAllowList(allowList []string) {
	plug.AllowList = allowList
}

func NewPosixPlugin() Plugin {
	return &PosixPlugin{
		params: make(map[string]*posixInfo),
	}
}
