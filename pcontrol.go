// Package pcontrol allows you to attach to a running process and call system calls from inside the attached process.
//
// It works on Linux and internally uses ptrace.
package pcontrol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"unsafe"

	"github.com/google/uuid"
	"gitlab.com/tozd/go/errors"
	"golang.org/x/sys/unix"
)

const (
	// These errno values are not really meant for user space programs (so they are not defined
	// in unix package) but we need them as we operate on a lower level and handle them in doSyscall.
	_ERESTARTSYS           = unix.Errno(512) //nolint: revive,stylecheck
	_ERESTARTNOINTR        = unix.Errno(513) //nolint: revive,stylecheck
	_ERESTARTNOHAND        = unix.Errno(514) //nolint: revive,stylecheck
	_ERESTART_RESTARTBLOCK = unix.Errno(516) //nolint: revive,stylecheck
)

// Errors are returned as negative numbers from syscalls but we compare them as uint64.
const maxErrno = uint64(0xfffffffffffff001)

const (
	dataSize    = 1024
	controlSize = 1024
)

// DefaultMemorySize is the default memory size of the allocated private working memory when attaching to the process.
const DefaultMemorySize = 4096

// We want to return -1 as uint64 so we need a variable to make Go happy.
var errorReturn = -1

func newMsghrd(start uint64, iov, control []byte) (uint64, []byte, errors.E) {
	buf := new(bytes.Buffer)
	// We build unix.Iovec.Base in the buffer.
	e := binary.Write(buf, binary.NativeEndian, iov)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Msghdr.Control in the buffer.
	e = binary.Write(buf, binary.NativeEndian, control)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Iovec in the buffer.
	// Base field.
	e = binary.Write(buf, binary.NativeEndian, start)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Len field.
	e = binary.Write(buf, binary.NativeEndian, uint64(len(iov)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	offset := uint64(buf.Len())
	// We build unix.Msghdr in the buffer.
	// Name field. Null pointer.
	e = binary.Write(buf, binary.NativeEndian, uint64(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Namelen field.
	e = binary.Write(buf, binary.NativeEndian, uint32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_0 field.
	e = binary.Write(buf, binary.NativeEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iov field.
	e = binary.Write(buf, binary.NativeEndian, start+uint64(len(iov))+uint64(len(control)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iovlen field.
	e = binary.Write(buf, binary.NativeEndian, uint64(1))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Control field.
	e = binary.Write(buf, binary.NativeEndian, start+uint64(len(iov)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Controllen field.
	e = binary.Write(buf, binary.NativeEndian, uint64(len(control)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Flags field.
	e = binary.Write(buf, binary.NativeEndian, int32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_1 field.
	e = binary.Write(buf, binary.NativeEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Sanity check.
	if uint64(buf.Len())-offset != uint64(unsafe.Sizeof(unix.Msghdr{})) {
		panic(errors.Errorf("Msghdr in buffer does not match the size of Msghdr"))
	}
	return offset, buf.Bytes(), nil
}

type Process struct {
	// Pid of the process to control (and attach to).
	Pid int
	// MemorySize of the allocated private working memory. Default is DefaultMemorySize.
	MemorySize uint64
	// LogWarnf is a function to call with any warning logging messages.
	LogWarnf      func(msg string, args ...any)
	memoryAddress uint64
}

// Attach attaches to the process and allocates private working memory in it.
//
// While the process is attached to, its regular execution is paused and only
// signal processing happens in the process.
func (p *Process) Attach() errors.E {
	if p.memoryAddress != 0 {
		return errors.Errorf("process already attached")
	}

	runtime.LockOSThread()

	err := errors.WithStack(unix.PtraceSeize(p.Pid))
	if err != nil {
		runtime.UnlockOSThread()
		return errors.Errorf("ptrace seize: %w", err)
	}

	err = errors.WithStack(unix.PtraceInterrupt(p.Pid))
	if err != nil {
		err = errors.Errorf("ptrace interrupt: %w", err)
		err2 := errors.WithStack(unix.PtraceDetach(p.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	err = p.waitTrap(unix.PTRACE_EVENT_STOP)
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(p.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	address, err := p.allocateMemory()
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(p.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	p.memoryAddress = address

	return nil
}

// Detach detaches from the process and frees the allocated private working memory in it.
func (p *Process) Detach() errors.E {
	if p.memoryAddress == 0 {
		return errors.Errorf("process not attached")
	}

	err := p.freeMemory(p.memoryAddress)
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(p.Pid))
		runtime.UnlockOSThread()
		if err2 == nil {
			p.memoryAddress = 0
		}
		return errors.Join(err, err2)
	}

	err = errors.WithStack(unix.PtraceDetach(p.Pid))
	runtime.UnlockOSThread()
	if err != nil {
		return errors.Errorf("ptrace detach: %w", err)
	}

	p.memoryAddress = 0

	return nil
}

// GetFds does a cross-process duplication of file descriptors from the (attached) process into this (host) process.
//
// It uses an abstract unix domain socket to get processFds from the process. If any of processFds
// are not found in the process, -1 is used in hostFds for it instead and no error is reported.
//
// You should close processFds afterwards if they are not needed anymore in the (attached) process.
// Same for hostFds in this (host) process.
func (p *Process) GetFds(processFds []int) (hostFds []int, err errors.E) {
	if p.memoryAddress == 0 {
		return nil, errors.Errorf("process not attached")
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, e := uuid.NewRandom()
	if e != nil {
		return nil, errors.WithStack(e)
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())

	processSocket, err := p.SysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err2 := p.SysClose(processSocket)
		err = errors.Join(err, err2)
	}()

	err = p.SysBindUnix(processSocket, addr)
	if err != nil {
		return nil, err
	}

	err = p.SysListen(processSocket, 1)
	if err != nil {
		return nil, err
	}

	connection, e := net.Dial("unix", addr)
	if e != nil {
		return nil, errors.Errorf("dial: %w", e)
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.Errorf("connection is %T and not net.UnixConn", connection)
	}

	processConnection, err := p.SysAccept(processSocket, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err2 := p.SysClose(processConnection)
		err = errors.Join(err, err2)
	}()

	for _, processFd := range processFds {
		// Encode the file descriptor.
		rights := unix.UnixRights(processFd)
		// Send it over. Write always returns error on short writes.
		// We send one byte data just to be sure everything gets through.
		_, _, err = p.SysSendmsg(processConnection, []byte{0}, rights, 0)
		if err != nil {
			if errors.Is(err, unix.EBADF) {
				hostFds = append(hostFds, -1)
				continue
			}
			return hostFds, err
		}

		// We could be more precise with needed sizes here, but it is good enough.
		iov := make([]byte, dataSize)
		control := make([]byte, controlSize)
		// TODO: What to do on short reads?
		_, controln, _, _, e := unixConnection.ReadMsgUnix(iov, control)
		if e != nil {
			return hostFds, errors.WithStack(e)
		}

		// The buffer might not been used fully.
		control = control[:controln]

		cmsgs, e := unix.ParseSocketControlMessage(control)
		if e != nil {
			return hostFds, errors.Errorf("ParseSocketControlMessage: %w", e)
		}

		for _, cmsg := range cmsgs {
			// Break memory aliasing in for loop to make the linter happy.
			cmsg := cmsg
			fds, e := unix.ParseUnixRights(&cmsg)
			if e != nil {
				return hostFds, errors.Errorf("ParseUnixRights: %w", e)
			}

			hostFds = append(hostFds, fds...)
		}
	}

	return hostFds, nil
}

// SetFd does a cross-process duplication of a file descriptor from this (host) process into the (attached) process.
//
// It uses an abstract unix domain socket to send hostFd to the process and then dup3 syscall
// to set that file descriptor to processFd in the process (any previous processFd is closed
// by dup3).
//
// You should close hostFd afterwards if it is not needed anymore in this (host) process.
// Same for processFd in the (attached) process.
func (p *Process) SetFd(hostFd int, processFd int) (err errors.E) {
	if p.memoryAddress == 0 {
		return errors.Errorf("process not attached")
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, e := uuid.NewRandom()
	if e != nil {
		return errors.WithStack(e)
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())
	listen, e := net.Listen("unix", addr)
	if e != nil {
		return errors.Errorf("listen: %w", e)
	}
	defer listen.Close()

	// SOCK_DGRAM did not work so we use SOCK_STREAM.
	// See: https://stackoverflow.com/questions/76327509/sending-a-file-descriptor-from-go-to-c
	processSocket, err := p.SysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		err2 := p.SysClose(processSocket)
		err = errors.Join(err, err2)
	}()

	err = p.SysConnectUnix(processSocket, addr)
	if err != nil {
		return err
	}

	connection, e := listen.Accept()
	if e != nil {
		return errors.Errorf("accept: %w", e)
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.Errorf("connection is %T and not net.UnixConn", connection)
	}

	// Encode the file descriptor.
	rights := unix.UnixRights(hostFd)
	// Send it over. Write always returns error on short writes.
	// We send one byte data just to be sure everything gets through.
	_, _, e = unixConnection.WriteMsgUnix([]byte{0}, rights, nil)
	if e != nil {
		return errors.WithStack(e)
	}

	// We could be more precise with needed sizes here, but it is good enough.
	iov := make([]byte, dataSize)
	control := make([]byte, controlSize)
	// TODO: What to do on short reads?
	_, controln, _, err := p.SysRecvmsg(processSocket, iov, control, 0)
	if err != nil {
		return err
	}

	// The buffer might not been used fully.
	control = control[:controln]

	cmsgs, e := unix.ParseSocketControlMessage(control)
	if e != nil {
		return errors.Errorf("ParseSocketControlMessage: %w", e)
	}

	fds, e := unix.ParseUnixRights(&cmsgs[0])
	if e != nil {
		return errors.Errorf("ParseUnixRights: %w", e)
	}

	fd := fds[0]

	err = p.SysDup3(fd, processFd)
	if err != nil {
		return err
	}

	err = p.SysClose(fd)
	if err != nil {
		return err
	}

	return nil
}

func (p *Process) memorySize() uint64 {
	if p.MemorySize == 0 {
		return DefaultMemorySize
	}
	return p.MemorySize
}

// Allocate private segment of memory in the process. We use it as
// the working memory for syscalls. Memory is configured to be
// executable as well and we store opcodes to run into it as well.
func (p *Process) allocateMemory() (uint64, errors.E) {
	addr, err := p.doSyscall(false, unix.SYS_MMAP, func(start uint64) ([]byte, [6]uint64, errors.E) {
		fd := -1
		return nil, [6]uint64{
			0,              // addr.
			p.memorySize(), // length.
			unix.PROT_EXEC | unix.PROT_READ | unix.PROT_WRITE, // prot.
			unix.MAP_PRIVATE | unix.MAP_ANONYMOUS,             // flags.
			uint64(fd),                                        // fd.
			0,                                                 // offset.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("allocate memory: %w", err)
	}
	return addr, err
}

// Free private segment of memory in the process.
func (p *Process) freeMemory(address uint64) errors.E {
	_, err := p.doSyscall(false, unix.SYS_MUNMAP, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			address,        // addr.
			p.memorySize(), // length.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("free memory: %w", err)
	}
	return err
}

// Getpid invokes getpid syscall in the (attached) process.
func (p *Process) SysGetpid() (int, errors.E) {
	pid, err := p.doSyscall(true, unix.SYS_GETPID, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{}, nil
	})
	if err != nil {
		err = errors.Errorf("sys getpid: %w", err)
	}
	return int(pid), err
}

// SysSocket invokes socket syscall in the (attached) process.
func (p *Process) SysSocket(domain, typ, proto int) (int, errors.E) {
	fd, err := p.doSyscall(true, unix.SYS_SOCKET, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(domain), // domain.
			uint64(typ),    // type.
			uint64(proto),  // protocol.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys socket: %w", err)
	}
	return int(fd), err
}

// SysClose invokes close syscall in the (attached) process.
func (p *Process) SysClose(fd int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_CLOSE, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd), // fd.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys close: %w", err)
	}
	return err
}

// SysListen invokes listen syscall in the (attached) process.
func (p *Process) SysListen(fd, backlog int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_LISTEN, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),      // sockfd.
			uint64(backlog), // backlog.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys listen: %w", err)
	}
	return err
}

// SysAccept invokes accept syscall in the (attached) process.
func (p *Process) SysAccept(fd, flags int) (int, errors.E) {
	connFd, err := p.doSyscall(true, unix.SYS_ACCEPT4, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),    // sockfd.
			0,             // addr.
			0,             // addrlen.
			uint64(flags), // flags.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys accept: %w", err)
	}
	return int(connFd), err
}

// SysDup3 invokes dup3 syscall in the (attached) process.
func (p *Process) SysDup3(oldFd, newFd int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_DUP3, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(oldFd), // oldfd.
			uint64(newFd), // newfd.
			0,             // flags.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys dup3: %w", err)
	}
	return err
}

// SysConnectUnix invokes connect syscall in the (attached) process for AF_UNIX socket path.
//
// If path starts with @, it is replaced with null character to connect to an abstract unix domain socket.
func (p *Process) SysConnectUnix(fd int, path string) errors.E {
	return p.connectOrBindUnix(unix.SYS_CONNECT, "connect", fd, path)
}

// SysBindUnix invokes bind syscall in the (attached) process for AF_UNIX socket path.
//
// If path starts with @, it is replaced with null character to bind to an abstract unix domain socket.
func (p *Process) SysBindUnix(fd int, path string) errors.E {
	return p.connectOrBindUnix(unix.SYS_BIND, "bind", fd, path)
}

// Both connect and bind system calls take the same arguments, so we have one method for both.
func (p *Process) connectOrBindUnix(call int, name string, fd int, path string) errors.E {
	_, err := p.doSyscall(true, call, func(start uint64) ([]byte, [6]uint64, errors.E) {
		buf := new(bytes.Buffer)
		// We build unix.RawSockaddrUnix in the buffer.
		// Family field.
		e := binary.Write(buf, binary.NativeEndian, uint16(unix.AF_UNIX))
		if e != nil {
			return nil, [6]uint64{}, errors.WithStack(e)
		}
		p := []byte(path)
		abstract := false
		// If it starts with @, it is an abstract unix domain socket.
		// We change @ to a null character.
		if p[0] == '@' {
			p[0] = 0
			abstract = true
		} else if p[0] == 0 {
			abstract = true
		}
		// Path field.
		e = binary.Write(buf, binary.NativeEndian, p)
		if e != nil {
			return nil, [6]uint64{}, errors.WithStack(e)
		}
		if !abstract {
			// If not abstract, then write a null character.
			e = binary.Write(buf, binary.NativeEndian, uint8(0))
			if e != nil {
				return nil, [6]uint64{}, errors.WithStack(e)
			}
		}
		// Sanity check.
		if uint64(buf.Len()) > uint64(unsafe.Sizeof(unix.RawSockaddrUnix{})) {
			return nil, [6]uint64{}, errors.Errorf("path too long")
		}
		payload := buf.Bytes()
		return payload, [6]uint64{
			uint64(fd),           // sockfd.
			start,                // addr.
			uint64(len(payload)), // addrlen.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys %s unix: %w", name, err)
	}
	return err
}

// SysSendmsg invokes sendmsg syscall in the (attached) process.
func (p *Process) SysSendmsg(fd int, iov, control []byte, flags int) (int, int, errors.E) {
	var payload []byte
	res, err := p.doSyscall(true, unix.SYS_SENDMSG, func(start uint64) ([]byte, [6]uint64, errors.E) {
		offset, pl, err := newMsghrd(start, iov, control)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		payload = pl
		return payload, [6]uint64{
			uint64(fd),     // sockfd.
			start + offset, // msg.
			uint64(flags),  // flags.
		}, nil
	})
	if err != nil {
		return int(res), 0, errors.Errorf("sys sendmsg: %w", err)
	}
	return int(res), len(control), nil
}

// SysRecvmsg invokes recvmsg syscall in the (attached) process.
//
//nolint:gomnd
func (p *Process) SysRecvmsg(fd int, iov, control []byte, flags int) (int, int, int, errors.E) {
	var payload []byte
	res, err := p.doSyscall(true, unix.SYS_RECVMSG, func(start uint64) ([]byte, [6]uint64, errors.E) {
		offset, pl, err := newMsghrd(start, iov, control)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		payload = pl
		return payload, [6]uint64{
			uint64(fd),     // sockfd.
			start + offset, // msg.
			uint64(flags),  // flags.
		}, nil
	})
	if err != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", err)
	}
	buf := bytes.NewReader(payload)
	e := binary.Read(buf, binary.NativeEndian, iov) // unix.Iovec.Base.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	e = binary.Read(buf, binary.NativeEndian, control) // unix.Msghdr.Control.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	_, _ = io.CopyN(io.Discard, buf, 8) // unix.Iovec.Base field.
	_, _ = io.CopyN(io.Discard, buf, 8) // unix.Iovec.Len field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Name field.
	_, _ = io.CopyN(io.Discard, buf, 4) // Namelen field.
	_, _ = io.CopyN(io.Discard, buf, 4) // Pad_cgo_0 field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Iov field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Iovlen field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Control field.
	var controln uint64
	e = binary.Read(buf, binary.NativeEndian, &controln) // Controllen field.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	var recvflags int32
	e = binary.Read(buf, binary.NativeEndian, &recvflags) // Flags field.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	return int(res), int(controln), int(recvflags), nil
}

// Low-level call of a system call in the process. Use doSyscall instead.
// In almost all cases you want to use it with useMemory set to true to
// not change code of the process to run a syscall. (We use useMemory set
// to false only to obtain and free such memory.)
func (p *Process) syscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (result uint64, err errors.E) {
	if useMemory && p.memoryAddress == 0 {
		return uint64(errorReturn), errors.Errorf("process not attached")
	}

	var originalRegs processRegs
	originalRegs, err = getProcessRegs(p.Pid)
	if err != nil {
		return uint64(errorReturn), err
	}

	var start uint64
	var payload []byte
	var arguments [6]uint64
	var originalInstructions []byte
	if useMemory {
		start = p.memoryAddress
		payload, arguments, err = args(p.memoryAddress)
		if err != nil {
			return uint64(errorReturn), err
		}
		availableMemory := int(p.memorySize()) - len(syscallInstruction)
		if len(payload) > availableMemory {
			return uint64(errorReturn), errors.Errorf("syscall payload (%d B) is larger than available memory (%d B)", len(payload), availableMemory)
		}
	} else {
		// TODO: What happens if PC is not 64bit aligned?
		start = getProcessPC(&originalRegs)
		payload, arguments, err = args(start)
		if err != nil {
			return uint64(errorReturn), err
		}

		// TODO: What if payload is so large that it hits the end of the data section?
		originalInstructions, err = p.readData(uintptr(start), len(payload)+len(syscallInstruction))
		if err != nil {
			return uint64(errorReturn), err
		}
	}

	defer func() {
		err2 := setProcessRegs(p.Pid, &originalRegs)
		err = errors.Join(err, err2)
	}()

	if !useMemory {
		defer func() {
			err2 := p.writeData(uintptr(start), originalInstructions)
			err = errors.Join(err, err2)
		}()
	}

	err = p.writeData(uintptr(start), payload)
	if err != nil {
		return uint64(errorReturn), err
	}

	instructionPointer := start + uint64(len(payload))
	err = p.writeData(uintptr(instructionPointer), syscallInstruction[:])
	if err != nil {
		return uint64(errorReturn), err
	}

	newRegs := newSyscallRegs(&originalRegs, instructionPointer, call, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5])

	err = setProcessRegs(p.Pid, &newRegs)
	if err != nil {
		return uint64(errorReturn), err
	}

	err = p.runToBreakpoint()
	if err != nil {
		return uint64(errorReturn), err
	}

	var resultRegs processRegs
	resultRegs, err = getProcessRegs(p.Pid)
	if err != nil {
		return uint64(errorReturn), err
	}

	resReg := getSyscallResultReg(&resultRegs)
	if resReg > maxErrno {
		return uint64(errorReturn), errors.WithStack(unix.Errno(-resReg))
	}

	newPayload, err := p.readData(uintptr(start), len(payload))
	if err != nil {
		return uint64(errorReturn), err
	}
	copy(payload, newPayload)

	return resReg, nil
}

// Syscalls can be interrupted by signal handling and might abort. So we
// wrap them with a loop which retries them automatically if interrupted.
// We do not handle EAGAIN here on purpose, to not block in a loop.
func (p *Process) doSyscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (uint64, errors.E) {
	for {
		result, err := p.syscall(useMemory, call, args)
		if err != nil {
			if errors.Is(err, _ERESTARTSYS) {
				continue
			} else if errors.Is(err, _ERESTARTNOINTR) {
				continue
			} else if errors.Is(err, _ERESTARTNOHAND) {
				continue
			} else if errors.Is(err, _ERESTART_RESTARTBLOCK) {
				continue
			} else if errors.Is(err, unix.EINTR) {
				continue
			}
			// Go to return.
		}

		return result, err
	}
}

// Syscall invokes a syscall with given arguments and returns its return value.
//
// Arguments are returned from the args callback and can be provided through a byte slice or through
// 6 uint64 arguments. The byte slice is copied to the (attached) process memory (into allocated
// private working memory) at start and you can then reference that memory through 6 uint64 arguments.
//
// Return value is -1 on error and a corresponding errno value is returned as error.
func (p *Process) Syscall(call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (uint64, errors.E) {
	return p.doSyscall(true, call, args)
}

// Read from the memory of the process.
func (p *Process) readData(address uintptr, length int) ([]byte, errors.E) {
	data := make([]byte, length)
	n, e := unix.PtracePeekData(p.Pid, address, data)
	if e != nil {
		return nil, errors.Errorf("ptrace peekdata: %w", e)
	}
	if n != length {
		return nil, errors.Errorf("wanted to read %d bytes, but read %d bytes", length, n)
	}
	return data, nil
}

// Read into the memory of the process.
func (p *Process) writeData(address uintptr, data []byte) errors.E {
	n, e := unix.PtracePokeData(p.Pid, address, data)
	if e != nil {
		return errors.Errorf("ptrace pokedata: %w", e)
	}
	if n != len(data) {
		return errors.Errorf("wanted to write %d bytes, but wrote %d bytes", len(data), n)
	}
	return nil
}

// When we do a syscall we set opcodes to call a syscall and we put afterwards
// a breakpoint (see syscallInstruction). This function executes those opcodes
// and returns once we hit the breakpoint. During execution signal handlers
// of the trustee might run as well before the breakpoint is reached (this is
// why we use ptrace cont with a breakpoint and not ptrace single step).
func (p *Process) runToBreakpoint() errors.E {
	err := errors.WithStack(unix.PtraceCont(p.Pid, 0))
	if err != nil {
		return errors.Errorf("run to breakpoint: %w", err)
	}

	// 0 trap cause means a breakpoint or single stepping.
	return p.waitTrap(0)
}

func (p *Process) waitTrap(cause int) errors.E {
	for {
		var status unix.WaitStatus
		var e error
		for {
			_, e = unix.Wait4(p.Pid, &status, 0, nil)
			if e == nil || !errors.Is(e, unix.EINTR) {
				break
			}
		}
		if e != nil {
			return errors.Errorf("wait trap: %w", e)
		}
		// A breakpoint or other trap cause we expected has been reached.
		if status.TrapCause() == cause {
			return nil
		} else if status.TrapCause() != -1 {
			if p.LogWarnf != nil {
				p.LogWarnf("unexpected trap cause for PID %d: %d, expected %d", p.Pid, status.TrapCause(), cause)
			}
			return nil
		} else if status.Stopped() {
			// If the process stopped it might have stopped for some other signal. While a process is
			// ptraced any signal it receives stops the process for us to decide what to do about the
			// signal. In our case we just pass the signal back to the process using ptrace cont and
			// let its signal handler do its work.
			err := errors.WithStack(unix.PtraceCont(p.Pid, int(status.StopSignal())))
			if err != nil {
				return errors.Errorf("wait trap: ptrace cont with %d: %w", int(status.StopSignal()), err)
			}
			continue
		}
		return errors.Errorf(
			"wait trap: unexpected wait status after wait, exit status %d, signal %d, stop signal %d, trap cause %d, expected trap cause %d",
			status.ExitStatus(), status.Signal(), status.StopSignal(), status.TrapCause(), cause,
		)
	}
}

// EqualFds returns true if both file descriptors point to the same underlying file.
func EqualFds(fd1, fd2 int) (bool, errors.E) {
	var stat1 unix.Stat_t
	err := errors.WithStack(unix.Fstat(fd1, &stat1))
	if err != nil {
		return false, err
	}
	var stat2 unix.Stat_t
	err = errors.WithStack(unix.Fstat(fd2, &stat2))
	if err != nil {
		return false, err
	}
	return stat1.Dev == stat2.Dev && stat1.Ino == stat2.Ino && stat1.Rdev == stat2.Rdev, nil
}
