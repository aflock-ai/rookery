package omnitrail

type Envelope struct {
	Header  Header              `json:"header"`
	Mapping map[string]*Element `json:"mapping"`
}

type Header struct {
	Features map[string]Feature `json:"features"`
}

type Feature struct {
	Algorithms []string `json:"algorithms,omitempty"`
}

type Element struct {
	Type         string `json:"type"`
	Sha1         string `json:"sha1,omitempty"`
	Sha256       string `json:"sha256,omitempty"`
	Sha1Gitoid   string `json:"gitoid:sha1,omitempty"`
	Sha256Gitoid string `json:"gitoid:sha256,omitempty"`
	Posix        *Posix `json:"posix,omitempty"`
}

type Posix struct {
	ATime              string `json:"atime,omitempty"`
	CTime              string `json:"ctime,omitempty"`
	CreationTime       string `json:"creation_time,omitempty"`
	ExtendedAttributes string `json:"extended_attributes,omitempty"`
	FileDeviceID       string `json:"file_device_id,omitempty"`
	FileFlags          string `json:"file_flags,omitempty"`
	FileInode          string `json:"file_inode,omitempty"`
	FileSystemID       string `json:"file_system_id,omitempty"`
	FileType           string `json:"file_type,omitempty"`
	HardLinkCount      string `json:"hard_link_count,omitempty"`
	MTime              string `json:"mtime,omitempty"`
	MetadataCTime      string `json:"metadata_ctime,omitempty"`
	OwnerGID           string `json:"owner_gid,omitempty"`
	OwnerUID           string `json:"owner_uid,omitempty"`
	Permissions        string `json:"permissions,omitempty"`
	Size               string `json:"size,omitempty"`
}

type Factory interface {
	Add(originalPath string) error
	Sha1ADGs() map[string]string
	Sha256ADGs() map[string]string
	Envelope() *Envelope
}

type Option func(o *Options)

type Options struct {
	Sha1Enabled   bool
	Sha256Enabled bool
}

type Plugin interface {
	Add(path string) error
	Store(envelope *Envelope) error
	Sha1ADG(map[string]string)
	Sha256ADG(map[string]string)
	SetAllowList([]string)
}
