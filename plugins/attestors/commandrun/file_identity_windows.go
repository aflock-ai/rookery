// Copyright 2021 The Witness Contributors
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

//go:build windows

package commandrun

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileBasicInfo and fileIDInfo are FILE_BASIC_INFO and FILE_ID_INFO, which
// golang.org/x/sys/windows does not define.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// openForHashing opens `path` once for reading with a share mode that admits
// readers only. While the handle is open no other process can open the file
// for write or delete it, so the read cannot be torn by a writer and the
// bracket no longer rests on a timestamp a writer can restore. A file already
// open for writing fails the open with a sharing violation, which is reported
// like any unreadable program: the digest is withheld, not weakened.
func openForHashing(path string) (*os.File, error) {
	pathResolutions.Add(1)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

func bracketBefore(f *os.File, _ os.FileInfo) (os.FileInfo, error) { return statForBracket(f) }

// statForBracket stats the handle and attaches the identity read from it.
// When any part of the identity cannot be read it returns the plain stat,
// which identityFromInfo reports as uncomparable: the read is refused rather
// than bracketed on size and modification time.
func statForBracket(f *os.File) (os.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	var basic fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return fi, nil
	}
	var vol uint64
	var fid [16]byte
	var idi fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&idi)), uint32(unsafe.Sizeof(idi))); err == nil {
		vol, fid = idi.VolumeSerialNumber, idi.FileID
	} else {
		// FAT and some network volumes have no 128-bit id; the 64-bit index
		// plus the volume serial is still the file's identity there.
		var bhi windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &bhi); err != nil {
			return fi, nil
		}
		vol = uint64(bhi.VolumeSerialNumber)
		idx := uint64(bhi.FileIndexHigh)<<32 | uint64(bhi.FileIndexLow)
		for i := 0; i < 8; i++ {
			fid[i] = byte(idx >> (8 * i))
		}
	}
	id, ok := windowsFileIdentity(vol, fid, basic.ChangeTime, fi.Size())
	if !ok {
		return fi, nil
	}
	return &handleInfo{FileInfo: fi, id: id}, nil
}

// identityFromInfo accepts only a stat that carries a handle identity. A
// plain FileInfo (size and modification time) is not comparable here: that was
// the weak bracket this replaces.
func identityFromInfo(st os.FileInfo) (fileIdentity, bool) {
	if h, ok := st.(*handleInfo); ok {
		return h.id, true
	}
	return fileIdentity{}, false
}
