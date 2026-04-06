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

//go:build linux

package commandrun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"golang.org/x/sys/unix"
)

const (
	MAX_PATH_LEN = 4096
)

type ptraceContext struct {
	parentPid           int
	mainProgram         string
	processes           map[int]*ProcessInfo
	exitCode            int
	hash                []cryptoutil.DigestValue
	environmentCapturer attestation.EnvironmentCapturer
	// tlsPendingFDs tracks file descriptors that connected to port 443
	// so we can extract TLS SNI from the first write on that fd.
	// Key: "pid:fd", Value: index into the process's Connections slice.
	tlsPendingFDs map[string]int
}

func enableTracing(c *exec.Cmd) {
	c.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
}

func (r *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		parentPid:           c.Process.Pid,
		mainProgram:         c.Path,
		processes:           make(map[int]*ProcessInfo),
		hash:                actx.Hashes(),
		environmentCapturer: actx.EnvironmentCapturer(),
		tlsPendingFDs:       make(map[string]int),
	}

	if err := pctx.runTrace(); err != nil {
		return nil, err
	}

	r.ExitCode = pctx.exitCode

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}

	return pctx.procInfoArray(), nil
}

func (p *ptraceContext) runTrace() error {
	defer p.retryOpenedFiles()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(p.parentPid, &status, 0, nil)
	if err != nil {
		return err
	}

	if err := unix.PtraceSetOptions(p.parentPid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return err
	}

	procInfo := p.getProcInfo(p.parentPid)
	procInfo.Program = p.mainProgram
	if err := unix.PtraceSyscall(p.parentPid, 0); err != nil {
		return err
	}

	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			return err
		}
		if pid == p.parentPid && status.Exited() {
			p.exitCode = status.ExitStatus()
			return nil
		}

		sig := status.StopSignal()
		// since we set PTRACE_O_TRACESYSGOOD any traps triggered by ptrace will have its signal set to SIGTRAP|0x80.
		// If we catch a signal that isn't a ptrace'd signal we want to let the process continue to handle that signal, so we inject the thrown signal back to the process.
		// If it was a ptrace SIGTRAP we suppress the signal and send 0
		injectedSig := int(sig)
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig
		if status.Stopped() && isPtraceTrap {
			injectedSig = 0
			if err := p.nextSyscall(pid); err != nil {
				log.Debugf("(tracing) got error while processing syscall: %v", err)
			}
		}

		if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
			log.Debugf("(tracing) got error from ptrace syscall: %v", err)
		}
	}
}

func (p *ptraceContext) retryOpenedFiles() {
	// after tracing, look through opened files to try to resolve any newly created files
	procInfo := p.getProcInfo(p.parentPid)

	for file, digestSet := range procInfo.OpenedFiles {
		if digestSet != nil {
			continue
		}

		newDigest, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)

		if err != nil {
			delete(procInfo.OpenedFiles, file)
			continue
		}

		procInfo.OpenedFiles[file] = newDigest
	}
}

func (p *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := p.handleSyscall(pid, regs); err != nil {
			return err
		}
	}

	return nil
}

func (p *ptraceContext) handleSyscall(pid int, regs unix.PtraceRegs) error { //nolint:gocognit,gocyclo,funlen
	argArray := getSyscallArgs(regs)
	syscallId := getSyscallId(regs)

	switch syscallId {
	case unix.SYS_EXECVE:
		procInfo := p.getProcInfo(pid)

		program, err := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
		if err == nil {
			procInfo.Program = program
		}

		exeLocation := fmt.Sprintf("/proc/%d/exe", procInfo.ProcessID)
		commLocation := fmt.Sprintf("/proc/%d/comm", procInfo.ProcessID)
		envinLocation := fmt.Sprintf("/proc/%d/environ", procInfo.ProcessID)
		cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", procInfo.ProcessID)
		status := fmt.Sprintf("/proc/%d/status", procInfo.ProcessID)

		// read status file and set attributes on success
		statusFile, err := os.ReadFile(status) //nolint:gosec
		if err == nil {
			procInfo.SpecBypassIsVuln = getSpecBypassIsVulnFromStatus(statusFile)
			ppid, err := getPPIDFromStatus(statusFile)
			if err == nil {
				procInfo.ParentPID = ppid
			}
		}

		comm, err := os.ReadFile(commLocation) //nolint:gosec
		if err == nil {
			procInfo.Comm = cleanString(string(comm))
		}

		environ, err := os.ReadFile(envinLocation) //nolint:gosec
		if err == nil && p.environmentCapturer != nil {
			allVars := strings.Split(string(environ), "\x00")

			capturedEnv := p.environmentCapturer.Capture(allVars)
			env := make([]string, 0, len(capturedEnv))
			for k, v := range capturedEnv {
				env = append(env, fmt.Sprintf("%s=%s", k, v))
			}

			procInfo.Environ = strings.Join(env, " ")
		}

		cmdline, err := os.ReadFile(cmdlineLocation) //nolint:gosec // G304: reading /proc/<pid>/cmdline
		if err == nil {
			procInfo.Cmdline = cleanString(string(cmdline))
		}

		exeDigest, err := cryptoutil.CalculateDigestSetFromFile(exeLocation, p.hash)
		if err == nil {
			procInfo.ExeDigest = exeDigest
		}

		if program != "" {
			programDigest, err := cryptoutil.CalculateDigestSetFromFile(program, p.hash)
			if err == nil {
				procInfo.ProgramDigest = programDigest
			}

		}

	case unix.SYS_OPENAT:
		file, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err != nil {
			return err
		}

		procInfo := p.getProcInfo(pid)
		digestSet, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
		if err != nil {
			if _, isPathErr := err.(*os.PathError); isPathErr {
				procInfo.OpenedFiles[file] = nil
			}

			return err
		}

		procInfo.OpenedFiles[file] = digestSet

	case unix.SYS_SOCKET:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		domain := int(argArray[0])
		sockType := int(argArray[1])
		protocol := int(argArray[2])

		procInfo.Network.Sockets = append(procInfo.Network.Sockets, SocketInfo{
			Family:   socketFamilyName(domain),
			Type:     socketTypeName(sockType),
			Protocol: protocol,
			FD:       -1, // fd not available at syscall entry
		})

	case unix.SYS_CONNECT:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		conn, err := p.parseSockaddr(pid, argArray[1], argArray[2], "connect")
		if err != nil {
			log.Debugf("(tracing) failed to parse connect sockaddr: %v", err)
			return nil // non-fatal
		}
		conn.FD = int(argArray[0])
		procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)

		// Track TLS connections for SNI extraction on next write
		if conn.Port == 443 && (conn.Family == "AF_INET" || conn.Family == "AF_INET6") {
			key := fmt.Sprintf("%d:%d", pid, conn.FD)
			p.tlsPendingFDs[key] = len(procInfo.Network.Connections) - 1
		}

		// Heuristic: connect to port 53 is likely DNS
		if conn.Port == 53 {
			procInfo.Network.DNSLookups = append(procInfo.Network.DNSLookups, DNSLookup{
				ServerAddress: conn.Address,
				ServerPort:    conn.Port,
			})
		}

	case unix.SYS_BIND:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)

		conn, err := p.parseSockaddr(pid, argArray[1], argArray[2], "bind")
		if err != nil {
			log.Debugf("(tracing) failed to parse bind sockaddr: %v", err)
			return nil
		}
		conn.FD = int(argArray[0])
		procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)

	case unix.SYS_SENDTO:
		// sendto(fd, buf, len, flags, dest_addr, addrlen)
		// Only record if dest_addr is non-null (UDP sends with explicit destination)
		if argArray[4] != 0 {
			procInfo := p.getProcInfo(pid)
			p.ensureNetwork(procInfo)

			conn, err := p.parseSockaddr(pid, argArray[4], argArray[5], "sendto")
			if err != nil {
				log.Debugf("(tracing) failed to parse sendto sockaddr: %v", err)
				return nil
			}
			conn.FD = int(argArray[0])
			procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)
		}

	case unix.SYS_SENDMSG:
		procInfo := p.getProcInfo(pid)
		p.ensureNetwork(procInfo)
		log.Debugf("(tracing) pid %d called sendmsg on fd %d", pid, int(argArray[0]))

	// --- File mutation syscalls ---

	case unix.SYS_WRITE, 18: // 18 = SYS_PWRITE64 on amd64
		fd := int(argArray[0])
		byteCount := int(argArray[2])

		// TLS SNI extraction: if this fd has a pending TLS connect, peek at
		// the write buffer for a ClientHello and extract the SNI hostname.
		if byteCount > 11 && byteCount < 16384 {
			key := fmt.Sprintf("%d:%d", pid, fd)
			if connIdx, ok := p.tlsPendingFDs[key]; ok {
				delete(p.tlsPendingFDs, key) // only try once per fd
				if hostname := p.extractTLSSNI(pid, argArray[1], byteCount); hostname != "" {
					procInfo := p.getProcInfo(pid)
					if procInfo.Network != nil && connIdx < len(procInfo.Network.Connections) {
						procInfo.Network.Connections[connIdx].Hostname = hostname
						log.Debugf("(tracing) TLS SNI: pid %d fd %d → %s", pid, fd, hostname)
					}
				}
			}
		}

		// Track writes by resolving fd to path via /proc/pid/fd/N
		// Only track writes to real files (skip stdout/stderr/pipes: fd 0,1,2)
		if fd > 2 && byteCount > 0 {
			path := p.resolveFD(pid, fd)
			if path != "" && !strings.HasPrefix(path, "pipe:") && !strings.HasPrefix(path, "socket:") && !strings.HasPrefix(path, "anon_inode:") {
				procInfo := p.getProcInfo(pid)
				p.ensureFileOps(procInfo)
				procInfo.FileOps.Writes = append(procInfo.FileOps.Writes, FileWrite{
					Path:      path,
					Bytes:     byteCount,
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}

	case unix.SYS_RENAMEAT2:
		// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		oldPath, err1 := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		newPath, err2 := p.readSyscallReg(pid, argArray[3], MAX_PATH_LEN)
		if err1 == nil && err2 == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Renames = append(procInfo.FileOps.Renames, FileRename{
				OldPath:   oldPath,
				NewPath:   newPath,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_UNLINKAT:
		// unlinkat(dirfd, pathname, flags)
		path, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err == nil {
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.Deletes = append(procInfo.FileOps.Deletes, FileDelete{
				Path:      path,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_FCHMODAT:
		// fchmodat(dirfd, pathname, mode, flags)
		path, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		if err == nil {
			mode := uint32(argArray[2])
			procInfo := p.getProcInfo(pid)
			p.ensureFileOps(procInfo)
			procInfo.FileOps.PermChanges = append(procInfo.FileOps.PermChanges, FilePermChange{
				Path:      path,
				Mode:      mode,
				SetExec:   mode&0111 != 0, // any execute bit set
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	// --- Security-sensitive syscalls ---

	case unix.SYS_MEMFD_CREATE:
		// memfd_create(name, flags) — fileless execution: creates anonymous executable memory
		name, _ := p.readSyscallReg(pid, argArray[0], 256)
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "memfd_create",
			Detail:    fmt.Sprintf("anonymous memory file: %s (flags: %d) — used for fileless code execution", name, int(argArray[1])),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_PTRACE:
		// If the traced process itself calls ptrace — anti-debugging or process injection
		request := int(argArray[0])
		targetPid := int(argArray[1])
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "ptrace",
			Detail:    fmt.Sprintf("ptrace request=%d target_pid=%d — anti-debugging or process injection", request, targetPid),
			Args:      []int{request, targetPid},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_MOUNT:
		// mount(source, target, filesystemtype, mountflags, data)
		source, _ := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
		target, _ := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
		fstype, _ := p.readSyscallReg(pid, argArray[2], 256)
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "mount",
			Detail:    fmt.Sprintf("mount %s on %s (type: %s) — potential container escape", source, target, fstype),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_CLONE, unix.SYS_CLONE3:
		// Track clone flags for namespace manipulation detection
		flags := int(argArray[0])
		suspicious := false
		var flagNames []string
		if flags&unix.CLONE_NEWNS != 0 {
			flagNames = append(flagNames, "CLONE_NEWNS")
			suspicious = true
		}
		if flags&unix.CLONE_NEWPID != 0 {
			flagNames = append(flagNames, "CLONE_NEWPID")
			suspicious = true
		}
		if flags&unix.CLONE_NEWNET != 0 {
			flagNames = append(flagNames, "CLONE_NEWNET")
			suspicious = true
		}
		if flags&unix.CLONE_NEWUSER != 0 {
			flagNames = append(flagNames, "CLONE_NEWUSER")
			suspicious = true
		}
		if suspicious {
			procInfo := p.getProcInfo(pid)
			procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
				Syscall:   "clone",
				Detail:    fmt.Sprintf("clone with namespace flags: %s — potential container escape or sandbox evasion", strings.Join(flagNames, "|")),
				Args:      []int{flags},
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	// --- Tier 1 additions from security research ---

	case unix.SYS_DUP3, 33: // 33 = SYS_DUP2 on amd64 (not defined on arm64)
		// dup2(oldfd, newfd) — critical for reverse shell detection
		// Pattern: socket→connect→dup2(sockfd,0)→dup2(sockfd,1)→dup2(sockfd,2)→execve("/bin/sh")
		oldFD := int(argArray[0])
		newFD := int(argArray[1])
		// Only record when redirecting a SOCKET to stdin/stdout/stderr
		// Pipe redirects (pip subprocess I/O) are normal and noisy
		if newFD <= 2 {
			oldPath := p.resolveFD(pid, oldFD)
			if strings.HasPrefix(oldPath, "socket:") {
				procInfo := p.getProcInfo(pid)
				target := []string{"stdin", "stdout", "stderr"}[newFD]
				procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
					Syscall:   "dup2",
					Detail:    fmt.Sprintf("redirected SOCKET fd %d (%s) to %s — reverse shell pattern", oldFD, oldPath, target),
					Args:      []int{oldFD, newFD},
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}

	case unix.SYS_MPROTECT:
		// mprotect(addr, len, prot) — making memory executable
		// Pattern: mmap(RW)→write(shellcode)→mprotect(RX) = fileless payload
		prot := int(argArray[2])
		if prot&unix.PROT_EXEC != 0 {
			procInfo := p.getProcInfo(pid)
			procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
				Syscall:   "mprotect",
				Detail:    fmt.Sprintf("made memory executable (addr=%#x len=%d prot=%d) — fileless payload indicator", argArray[0], int(argArray[1]), prot),
				Args:      []int{int(argArray[0]), int(argArray[1]), prot},
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}

	case unix.SYS_PRCTL:
		// prctl(option, ...) — process self-modification
		option := int(argArray[0])
		procInfo := p.getProcInfo(pid)
		var detail string
		switch option {
		case 15: // PR_SET_NAME
			name, _ := p.readSyscallReg(pid, argArray[1], 16)
			detail = fmt.Sprintf("PR_SET_NAME: renamed process to '%s' — hiding malicious process identity", name)
		case 4: // PR_SET_DUMPABLE
			detail = fmt.Sprintf("PR_SET_DUMPABLE=%d — may prevent forensic core dumps", int(argArray[1]))
		case 38: // PR_SET_NO_NEW_PRIVS
			detail = fmt.Sprintf("PR_SET_NO_NEW_PRIVS=%d — seccomp setup", int(argArray[1]))
		default:
			// Only log notable prctl options
			return nil
		}
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "prctl",
			Detail:    detail,
			Args:      []int{option, int(argArray[1])},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_SETSID:
		// setsid() — create new session, detach from terminal
		// Used to daemonize malicious processes
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "setsid",
			Detail:    "created new session — daemonizing to detach from install process tree",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_SETNS:
		// setns(fd, nstype) — join existing namespace
		nstype := int(argArray[1])
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "setns",
			Detail:    fmt.Sprintf("joined namespace (fd=%d type=%d) — container escape or sandbox evasion", int(argArray[0]), nstype),
			Args:      []int{int(argArray[0]), nstype},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})

	case unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE:
		// Kernel module loading — rootkit installation
		procInfo := p.getProcInfo(pid)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "init_module",
			Detail:    "attempted to load kernel module — rootkit installation",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}

	return nil
}

// ensureNetwork initializes the NetworkActivity struct if nil.
func (p *ptraceContext) ensureNetwork(procInfo *ProcessInfo) {
	if procInfo.Network == nil {
		procInfo.Network = &NetworkActivity{}
	}
}

// ensureFileOps initializes the FileActivity struct if nil.
func (p *ptraceContext) ensureFileOps(procInfo *ProcessInfo) {
	if procInfo.FileOps == nil {
		procInfo.FileOps = &FileActivity{}
	}
}

// resolveFD resolves a file descriptor to a path via /proc/pid/fd/N.
func (p *ptraceContext) resolveFD(pid, fd int) string {
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return target
}

// parseSockaddr reads a sockaddr struct from the traced process memory and
// extracts the address family, IP/path, and port.
func (p *ptraceContext) parseSockaddr(pid int, addrPtr uintptr, addrLen uintptr, syscallName string) (*NetworkConnection, error) {
	size := int(addrLen)
	if size < 2 || size > 128 {
		return nil, fmt.Errorf("sockaddr size %d out of range", size)
	}

	data := make([]byte, size)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(size),
	}
	remoteIov := unix.RemoteIovec{
		Base: addrPtr,
		Len:  size,
	}

	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		return nil, fmt.Errorf("ProcessVMReadv for sockaddr: %w", err)
	}

	family := binary.LittleEndian.Uint16(data[0:2])

	conn := &NetworkConnection{
		Syscall:   syscallName,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	switch family {
	case unix.AF_INET:
		if size < 8 {
			return nil, fmt.Errorf("AF_INET sockaddr too short: %d", size)
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := net.IPv4(data[4], data[5], data[6], data[7])
		conn.Family = "AF_INET"
		conn.Address = ip.String()
		conn.Port = int(port)

	case unix.AF_INET6:
		if size < 28 {
			return nil, fmt.Errorf("AF_INET6 sockaddr too short: %d", size)
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := net.IP(data[8:24])
		conn.Family = "AF_INET6"
		conn.Address = ip.String()
		conn.Port = int(port)

	case unix.AF_UNIX:
		// Path starts at offset 2, null-terminated
		pathEnd := bytes.IndexByte(data[2:], 0)
		if pathEnd < 0 {
			pathEnd = len(data) - 2
		}
		conn.Family = "AF_UNIX"
		conn.Address = string(data[2 : 2+pathEnd])

	default:
		conn.Family = fmt.Sprintf("AF_%d", family)
		conn.Address = fmt.Sprintf("raw:%x", data)
	}

	return conn, nil
}

func socketFamilyName(family int) string {
	switch family {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	case unix.AF_UNIX:
		return "AF_UNIX"
	case unix.AF_NETLINK:
		return "AF_NETLINK"
	default:
		return fmt.Sprintf("AF_%d", family)
	}
}

func socketTypeName(sockType int) string {
	// Mask off SOCK_NONBLOCK and SOCK_CLOEXEC flags
	base := sockType & 0xf
	switch base {
	case unix.SOCK_STREAM:
		return "SOCK_STREAM"
	case unix.SOCK_DGRAM:
		return "SOCK_DGRAM"
	case unix.SOCK_RAW:
		return "SOCK_RAW"
	case unix.SOCK_SEQPACKET:
		return "SOCK_SEQPACKET"
	default:
		return fmt.Sprintf("SOCK_%d", base)
	}
}

func (ctx *ptraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := ctx.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}

		ctx.processes[pid] = procInfo
	}

	return procInfo
}

func (ctx *ptraceContext) procInfoArray() []ProcessInfo {
	processes := make([]ProcessInfo, 0, len(ctx.processes))
	for _, procInfo := range ctx.processes {
		processes = append(processes, *procInfo)
	}

	return processes
}

func (ctx *ptraceContext) readSyscallReg(pid int, addr uintptr, n int) (string, error) {
	data := make([]byte, n)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(n),
	}

	removeIov := unix.RemoteIovec{
		Base: addr,
		Len:  n,
	}

	// ProcessVMReadv is much faster than PtracePeekData since it doesn't route the data through kernel space,
	// but there may be times where this doesn't work.  We may want to fall back to PtracePeekData if this fails
	numBytes, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{removeIov}, 0)
	if err != nil {
		return "", err
	}

	if numBytes == 0 {
		return "", nil
	}

	// don't want to use cgo... look for the first 0 byte for the end of the c string
	size := bytes.IndexByte(data, 0)
	if size < 0 {
		// No null terminator found; use the full buffer.
		size = numBytes
	}
	return string(data[:size]), nil
}

func cleanString(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", " "))
}

func getPPIDFromStatus(status []byte) (int, error) {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "PPid:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}
			ppid := strings.TrimSpace(parts[1])
			return strconv.Atoi(ppid)
		}
	}

	return 0, fmt.Errorf("PPid not found in status")
}

func getSpecBypassIsVulnFromStatus(status []byte) bool {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Speculation_Store_Bypass:") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}
			isVuln := strings.TrimSpace(parts[1])
			if strings.Contains(isVuln, "vulnerable") {
				return true
			}
		}
	}

	return false
}

// extractTLSSNI reads the write buffer from the traced process and parses
// the TLS ClientHello to extract the Server Name Indication (SNI) hostname.
// The SNI is plaintext in the ClientHello — no decryption needed.
//
// TLS record layout:
//   [0]     ContentType (0x16 = Handshake)
//   [1:3]   Version
//   [3:5]   Length
//   [5]     HandshakeType (0x01 = ClientHello)
//   [6:9]   Handshake length
//   [9:11]  ClientHello version
//   [11:43] Random (32 bytes)
//   [43]    SessionID length → skip SessionID
//   ...     CipherSuites length → skip
//   ...     Compression length → skip
//   ...     Extensions length
//   ...     Extensions: look for type 0x0000 (SNI)
func (p *ptraceContext) extractTLSSNI(pid int, bufPtr uintptr, bufLen int) string {
	// Read up to 512 bytes — SNI is always in the first few hundred bytes
	readLen := bufLen
	if readLen > 512 {
		readLen = 512
	}
	if readLen < 43 {
		return "" // too short for a ClientHello
	}

	data := make([]byte, readLen)
	localIov := unix.Iovec{Base: &data[0], Len: getNativeUint(readLen)}
	remoteIov := unix.RemoteIovec{Base: bufPtr, Len: readLen}

	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		return ""
	}

	// Verify TLS record header
	if data[0] != 0x16 { // not a Handshake record
		return ""
	}
	// recordLen := int(binary.BigEndian.Uint16(data[3:5]))

	// Verify ClientHello
	if len(data) < 6 || data[5] != 0x01 {
		return ""
	}

	// Skip: handshake header (4 bytes) + client version (2) + random (32) = offset 43
	pos := 43
	if pos >= readLen {
		return ""
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > readLen {
		return ""
	}

	// Cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > readLen {
		return ""
	}

	// Compression methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > readLen {
		return ""
	}

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > readLen {
		extensionsEnd = readLen
	}

	// Walk extensions looking for SNI (type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 && extLen > 5 && pos+extLen <= extensionsEnd {
			// SNI extension: list length (2) + type (1) + name length (2) + name
			sniListLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			if sniListLen > extLen-2 {
				break
			}
			nameType := data[pos+2]
			if nameType != 0 { // 0 = host_name
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
			nameStart := pos + 5
			nameEnd := nameStart + nameLen
			if nameEnd > extensionsEnd || nameLen == 0 || nameLen > 255 {
				break
			}
			hostname := string(data[nameStart:nameEnd])
			// Basic validation: hostname should be printable ASCII
			for _, c := range hostname {
				if c < 0x20 || c > 0x7e {
					return ""
				}
			}
			return hostname
		}

		pos += extLen
	}

	return ""
}
