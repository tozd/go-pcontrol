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

var (
	ErrProcessAlreadyAttached = errors.Base("process already attached")
	ErrProcessNotAttached     = errors.Base("process not attached")
	ErrOutOfMemory            = errors.Base("syscall payload is larger than available memory")
	ErrUnexpectedRead         = errors.Base("unexpected bytes read")
	ErrUnexpectedWrite        = errors.Base("unexpected bytes written")
	ErrUnexpectedWaitStatus   = errors.Base("unexpected wait status")
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

	memoryAlignmentBytes = 8
)

// DefaultMemorySize is the default memory size of the allocated private working memory when attaching to the process.
const DefaultMemorySize = 4096

// We want to return -1 as uint64 so we need a variable to make Go happy.
var errorReturn = -1 //nolint:gochecknoglobals

func newMsghrd(start uint64, iov, control []byte) (uint64, []byte, errors.E) {
	buf := new(bytes.Buffer)
	// We build unix.Iovec.Base in the buffer.
	e := binary.Write(buf, nativeEndian, iov)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Msghdr.Control in the buffer.
	e = binary.Write(buf, nativeEndian, control)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Iovec in the buffer.
	// Base field.
	e = binary.Write(buf, nativeEndian, start)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Len field.
	e = binary.Write(buf, nativeEndian, uint64(len(iov)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	offset := uint64(buf.Len()) //nolint:gosec
	// We build unix.Msghdr in the buffer.
	// Name field. Null pointer.
	e = binary.Write(buf, nativeEndian, uint64(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Namelen field.
	e = binary.Write(buf, nativeEndian, uint32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_0 field.
	e = binary.Write(buf, nativeEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iov field.
	e = binary.Write(buf, nativeEndian, start+uint64(len(iov))+uint64(len(control)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iovlen field.
	e = binary.Write(buf, nativeEndian, uint64(1))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Control field.
	e = binary.Write(buf, nativeEndian, start+uint64(len(iov)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Controllen field.
	e = binary.Write(buf, nativeEndian, uint64(len(control)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Flags field.
	e = binary.Write(buf, nativeEndian, int32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_1 field.
	e = binary.Write(buf, nativeEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Sanity check.
	if uint64(buf.Len())-offset != uint64(unsafe.Sizeof(unix.Msghdr{})) { //nolint:exhaustruct,gosec
		panic(errors.New("msghdr in buffer does not match the size of msghdr"))
	}
	return offset, buf.Bytes(), nil
}

func alignMemory(x uint64) uint64 {
	return ((x + (memoryAlignmentBytes - 1)) / memoryAlignmentBytes) * memoryAlignmentBytes
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
func (p *Process) Attach() (errE errors.E) { //nolint:nonamedreturns
	if p.memoryAddress != 0 {
		return errors.WithDetails(ErrProcessAlreadyAttached, "pid", p.Pid)
	}

	runtime.LockOSThread()

	err := unix.PtraceSeize(p.Pid)
	if err != nil {
		runtime.UnlockOSThread()
		errE = errors.WithMessage(err, "ptrace seize")
		errors.Details(errE)["pid"] = p.Pid
		return errE
	}

	defer func() {
		if errE != nil {
			err = unix.PtraceDetach(p.Pid)
			runtime.UnlockOSThread()
			if err != nil {
				errE2 := errors.WithMessage(err, "ptrace detach")
				errors.Details(errE2)["pid"] = p.Pid
				errE = errors.Join(errE, errE2)
			}
		}
	}()

	err = unix.PtraceInterrupt(p.Pid)
	if err != nil {
		errE = errors.WithMessage(err, "ptrace interrupt")
		errors.Details(errE)["pid"] = p.Pid
		return errE
	}

	errE = p.waitTrap(unix.PTRACE_EVENT_STOP)
	if errE != nil {
		errors.Details(errE)["pid"] = p.Pid
		return errE
	}

	address, errE := p.allocateMemory()
	if errE != nil {
		errors.Details(errE)["pid"] = p.Pid
		return errE
	}

	p.memoryAddress = address

	return nil
}

// Detach detaches from the process and frees the allocated private working memory in it.
func (p *Process) Detach() errors.E {
	if p.memoryAddress == 0 {
		return errors.WithDetails(ErrProcessNotAttached, "pid", p.Pid)
	}

	errE1 := p.freeMemory(p.memoryAddress)
	if errE1 != nil {
		errors.Details(errE1)["pid"] = p.Pid
		// We do not return the error here, we try to detatch the process as well.
	}

	err := unix.PtraceDetach(p.Pid)
	runtime.UnlockOSThread()
	if err != nil {
		errE2 := errors.WithMessage(err, "ptrace detach")
		errors.Details(errE2)["pid"] = p.Pid
		// errE1 can be nil here and then this is the same as return errE2.
		return errors.Join(errE1, errE2)
	}

	p.memoryAddress = 0

	return errE1
}

// GetFds does a cross-process duplication of file descriptors from the (attached) process into this (host) process.
//
// It uses an abstract unix domain socket to get processFds from the process. If any of processFds
// are not found in the process, -1 is used in hostFds for it instead and no error is reported.
//
// You should close processFds afterwards if they are not needed anymore in the (attached) process.
// Same for hostFds in this (host) process.
func (p *Process) GetFds(processFds []int) (hostFds []int, errE errors.E) { //nolint:nonamedreturns
	if p.memoryAddress == 0 {
		return nil, errors.WithDetails(ErrProcessNotAttached, "pid", p.Pid)
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.WithMessage(err, "uuid new")
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())

	processSocket, errE := p.SysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if errE != nil {
		return nil, errE
	}
	defer func() {
		errE2 := p.SysClose(processSocket)
		errE = errors.Join(errE, errE2)
	}()

	errE = p.SysBindUnix(processSocket, addr)
	if errE != nil {
		return nil, errE
	}

	errE = p.SysListen(processSocket, 1)
	if errE != nil {
		return nil, errE
	}

	connection, err := net.Dial("unix", addr)
	if err != nil {
		return nil, errors.WithMessage(err, "net dial")
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		panic(errors.Errorf("connection is %T and not net.UnixConn", connection))
	}

	processConnection, errE := p.SysAccept(processSocket, 0)
	if errE != nil {
		return nil, errE
	}
	defer func() {
		errE2 := p.SysClose(processConnection)
		errE = errors.Join(errE, errE2)
	}()

	for _, processFd := range processFds {
		// Encode the file descriptor.
		rights := unix.UnixRights(processFd)
		// Send it over. Write always returns error on short writes.
		// We send one byte data just to be sure everything gets through.
		_, _, errE = p.SysSendmsg(processConnection, []byte{0}, rights, 0)
		if errE != nil {
			if errors.Is(errE, unix.EBADF) {
				hostFds = append(hostFds, -1)
				continue
			}
			return hostFds, errE
		}

		// We could be more precise with needed sizes here, but it is good enough.
		iov := make([]byte, dataSize)
		control := make([]byte, controlSize)
		// TODO: What to do on short reads?
		_, controln, _, _, err := unixConnection.ReadMsgUnix(iov, control)
		if err != nil {
			return hostFds, errors.WithMessage(err, "read msg unix")
		}

		// The buffer might not been used fully.
		control = control[:controln]

		cmsgs, err := unix.ParseSocketControlMessage(control)
		if err != nil {
			return hostFds, errors.WithMessage(err, "parse socket control message")
		}

		for _, cmsg := range cmsgs {
			fds, err := unix.ParseUnixRights(&cmsg)
			if err != nil {
				return hostFds, errors.WithMessage(err, "parse unix rights")
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
func (p *Process) SetFd(hostFd int, processFd int) (errE errors.E) { //nolint:nonamedreturns
	if p.memoryAddress == 0 {
		return errors.WithDetails(ErrProcessNotAttached, "pid", p.Pid)
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, err := uuid.NewRandom()
	if err != nil {
		return errors.WithMessage(err, "uuid new")
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())
	listen, err := net.Listen("unix", addr)
	if err != nil {
		return errors.WithMessage(err, "net listen")
	}
	defer listen.Close()

	// SOCK_DGRAM did not work so we use SOCK_STREAM.
	// See: https://stackoverflow.com/questions/76327509/sending-a-file-descriptor-from-go-to-c
	processSocket, errE := p.SysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if errE != nil {
		return errE
	}
	defer func() {
		errE2 := p.SysClose(processSocket)
		errE = errors.Join(errE, errE2)
	}()

	errE = p.SysConnectUnix(processSocket, addr)
	if errE != nil {
		return errE
	}

	connection, err := listen.Accept()
	if err != nil {
		return errors.WithMessage(err, "accept")
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		panic(errors.Errorf("connection is %T and not net.UnixConn", connection))
	}

	// Encode the file descriptor.
	rights := unix.UnixRights(hostFd)
	// Send it over. Write always returns error on short writes.
	// We send one byte data just to be sure everything gets through.
	_, _, err = unixConnection.WriteMsgUnix([]byte{0}, rights, nil)
	if err != nil {
		return errors.WithMessage(err, "write msg unix")
	}

	// We could be more precise with needed sizes here, but it is good enough.
	iov := make([]byte, dataSize)
	control := make([]byte, controlSize)
	// TODO: What to do on short reads?
	_, controln, _, errE := p.SysRecvmsg(processSocket, iov, control, 0)
	if errE != nil {
		return errE
	}

	// The buffer might not been used fully.
	control = control[:controln]

	cmsgs, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return errors.WithMessage(err, "parse socket control message")
	}

	fds, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil {
		return errors.WithMessage(err, "parse unix rights")
	}

	fd := fds[0]

	errE = p.SysDup3(fd, processFd)
	if errE != nil {
		return errE
	}

	errE = p.SysClose(fd)
	if errE != nil {
		return errE
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
	addr, err := p.doSyscall(false, unix.SYS_MMAP, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		fd := -1
		return nil, [6]uint64{
			0,              // addr.
			p.memorySize(), // length.
			unix.PROT_EXEC | unix.PROT_READ | unix.PROT_WRITE, // prot.
			unix.MAP_PRIVATE | unix.MAP_ANONYMOUS,             // flags.
			uint64(fd),                                        //nolint:gosec // fd.
			0,                                                 // offset.
		}, nil
	})
	if addr == 0 {
		err = errors.New("invalid result")
	}
	return addr, errors.WithMessage(err, "allocate memory")
}

// Free private segment of memory in the process.
func (p *Process) freeMemory(address uint64) errors.E {
	_, err := p.doSyscall(false, unix.SYS_MUNMAP, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			address,        // addr.
			p.memorySize(), // length.
		}, nil
	})
	return errors.WithMessage(err, "free memory")
}

// Getpid invokes getpid syscall in the (attached) process.
func (p *Process) SysGetpid() (int, errors.E) {
	pid, err := p.doSyscall(true, unix.SYS_GETPID, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{}, nil
	})
	return int(pid), errors.WithMessage(err, "sys getpid") //nolint:gosec
}

// SysSocket invokes socket syscall in the (attached) process.
func (p *Process) SysSocket(domain, typ, proto int) (int, errors.E) {
	fd, err := p.doSyscall(true, unix.SYS_SOCKET, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(domain), //nolint:gosec // domain.
			uint64(typ),    //nolint:gosec // type.
			uint64(proto),  //nolint:gosec // protocol.
		}, nil
	})
	return int(fd), errors.WithMessage(err, "sys socket") //nolint:gosec
}

// SysClose invokes close syscall in the (attached) process.
func (p *Process) SysClose(fd int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_CLOSE, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd), //nolint:gosec // fd.
		}, nil
	})
	return errors.WithMessage(err, "sys close")
}

// SysListen invokes listen syscall in the (attached) process.
func (p *Process) SysListen(fd, backlog int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_LISTEN, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),      //nolint:gosec // sockfd.
			uint64(backlog), //nolint:gosec // backlog.
		}, nil
	})
	return errors.WithMessage(err, "sys listen")
}

// SysAccept invokes accept syscall in the (attached) process.
func (p *Process) SysAccept(fd, flags int) (int, errors.E) {
	connFd, err := p.doSyscall(true, unix.SYS_ACCEPT4, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),    //nolint:gosec // sockfd.
			0,             // addr.
			0,             // addrlen.
			uint64(flags), //nolint:gosec // flags.
		}, nil
	})
	return int(connFd), errors.WithMessage(err, "sys accept") //nolint:gosec
}

// SysDup3 invokes dup3 syscall in the (attached) process.
func (p *Process) SysDup3(oldFd, newFd int) errors.E {
	_, err := p.doSyscall(true, unix.SYS_DUP3, func(_ uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(oldFd), //nolint:gosec // oldfd.
			uint64(newFd), //nolint:gosec // newfd.
			0,             // flags.
		}, nil
	})
	return errors.WithMessage(err, "sys dup3")
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
		err := binary.Write(buf, nativeEndian, uint16(unix.AF_UNIX))
		if err != nil {
			return nil, [6]uint64{}, errors.WithStack(err)
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
		err = binary.Write(buf, nativeEndian, p)
		if err != nil {
			return nil, [6]uint64{}, errors.WithStack(err)
		}
		if !abstract {
			// If not abstract, then write a null character.
			err = binary.Write(buf, nativeEndian, uint8(0))
			if err != nil {
				return nil, [6]uint64{}, errors.WithStack(err)
			}
		}
		// Sanity check.
		if uint64(buf.Len()) > uint64(unsafe.Sizeof(unix.RawSockaddrUnix{})) { //nolint:exhaustruct,gosec
			panic(errors.New("path too long"))
		}
		payload := buf.Bytes()
		return payload, [6]uint64{
			uint64(fd),           //nolint:gosec // sockfd.
			start,                // addr.
			uint64(len(payload)), // addrlen.
		}, nil
	})
	return errors.WithMessagef(err, "sys %s unix", name)
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
			uint64(fd),     //nolint:gosec // sockfd.
			start + offset, // msg.
			uint64(flags),  //nolint:gosec // flags.
		}, nil
	})
	if err != nil {
		return int(res), 0, errors.WithMessage(err, "sys sendmsg") //nolint:gosec
	}
	return int(res), len(control), nil //nolint:gosec
}

// SysRecvmsg invokes recvmsg syscall in the (attached) process.
//
//nolint:mnd
func (p *Process) SysRecvmsg(fd int, iov, control []byte, flags int) (int, int, int, errors.E) {
	var payload []byte
	res, errE := p.doSyscall(true, unix.SYS_RECVMSG, func(start uint64) ([]byte, [6]uint64, errors.E) {
		offset, pl, err := newMsghrd(start, iov, control)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		payload = pl
		return payload, [6]uint64{
			uint64(fd),     //nolint:gosec // sockfd.
			start + offset, // msg.
			uint64(flags),  //nolint:gosec // flags.
		}, nil
	})
	if errE != nil {
		return int(res), 0, 0, errors.WithMessage(errE, "sys recvmsg") //nolint:gosec
	}
	buf := bytes.NewReader(payload)
	err := binary.Read(buf, nativeEndian, iov) // unix.Iovec.Base.
	if err != nil {
		return int(res), 0, 0, errors.WithMessage(err, "sys recvmsg") //nolint:gosec
	}
	err = binary.Read(buf, nativeEndian, control) // unix.Msghdr.Control.
	if err != nil {
		return int(res), 0, 0, errors.WithMessage(err, "sys recvmsg") //nolint:gosec
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
	err = binary.Read(buf, nativeEndian, &controln) // Controllen field.
	if err != nil {
		return int(res), 0, 0, errors.WithMessage(err, "sys recvmsg") //nolint:gosec
	}
	var recvflags int32
	err = binary.Read(buf, nativeEndian, &recvflags) // Flags field.
	if err != nil {
		return int(res), 0, 0, errors.WithMessage(err, "sys recvmsg") //nolint:gosec
	}
	return int(res), int(controln), int(recvflags), nil //nolint:gosec
}

// Low-level call of a system call in the process. Use doSyscall instead.
// In almost all cases you want to use it with useMemory set to true to
// not change code of the process to run a syscall. (We use useMemory set
// to false only to obtain and free such memory.)
func (p *Process) syscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (result uint64, err errors.E) { //nolint:nonamedreturns
	if useMemory && p.memoryAddress == 0 {
		return uint64(errorReturn), errors.WithDetails(ErrProcessNotAttached, "pid", p.Pid) //nolint:gosec
	}

	var originalRegs processRegs
	originalRegs, err = getProcessRegs(p.Pid)
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	var start uint64
	var payload []byte
	var payloadLength uint64
	var arguments [6]uint64
	var originalInstructions []byte
	if useMemory {
		start = p.memoryAddress
		payload, arguments, err = args(p.memoryAddress)
		if err != nil {
			errors.Details(err)["call"] = call
			return uint64(errorReturn), err //nolint:gosec
		}
		payloadLength = alignMemory(uint64(len(payload)))
		availableMemory := p.memorySize() - uint64(len(syscallInstruction))
		if payloadLength > availableMemory {
			return uint64(errorReturn), errors.WithDetails( //nolint:gosec
				ErrOutOfMemory,
				"call", call,
				"payload", payloadLength,
				"available", availableMemory,
			)
		}
	} else {
		start = alignMemory(getProcessPC(&originalRegs))
		payload, arguments, err = args(start)
		if err != nil {
			errors.Details(err)["call"] = call
			return uint64(errorReturn), err //nolint:gosec
		}

		payloadLength = alignMemory(uint64(len(payload)))
		// TODO: What if payload is so large that it hits the end of the data section?
		originalInstructions, err = p.readData(uintptr(start), int(payloadLength)+len(syscallInstruction)) //nolint:gosec
		if err != nil {
			errors.Details(err)["call"] = call
			return uint64(errorReturn), err //nolint:gosec
		}
	}

	defer func() {
		err2 := setProcessRegs(p.Pid, &originalRegs)
		if err2 != nil {
			errors.Details(err2)["call"] = call
		}
		err = errors.Join(err, err2)
	}()

	if !useMemory {
		defer func() {
			err2 := p.writeData(uintptr(start), originalInstructions)
			if err2 != nil {
				errors.Details(err2)["call"] = call
			}
			err = errors.Join(err, err2)
		}()
	}

	err = p.writeData(uintptr(start), payload)
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	instructionPointer := start + payloadLength
	err = p.writeData(uintptr(instructionPointer), syscallInstruction[:])
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	newRegs := newSyscallRegs(&originalRegs, instructionPointer, call, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5])

	err = setProcessRegs(p.Pid, &newRegs)
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	err = p.runToBreakpoint()
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	var resultRegs processRegs
	resultRegs, err = getProcessRegs(p.Pid)
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
	}

	resReg := getSyscallResultReg(&resultRegs)
	if resReg > maxErrno {
		return uint64(errorReturn), errors.WithDetails( //nolint:gosec
			unix.Errno(-resReg),
			"call", call,
		)
	}

	newPayload, err := p.readData(uintptr(start), len(payload))
	if err != nil {
		errors.Details(err)["call"] = call
		return uint64(errorReturn), err //nolint:gosec
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
	n, err := unix.PtracePeekData(p.Pid, address, data)
	if err != nil {
		return nil, errors.WithMessage(err, "ptrace peekdata")
	}
	if n != length {
		return nil, errors.WithDetails(
			ErrUnexpectedRead,
			"expected", length,
			"read", n,
		)
	}
	return data, nil
}

// Read into the memory of the process.
func (p *Process) writeData(address uintptr, data []byte) errors.E {
	n, err := unix.PtracePokeData(p.Pid, address, data)
	if err != nil {
		return errors.WithMessage(err, "ptrace pokedata")
	}
	if n != len(data) {
		return errors.WithDetails(
			ErrUnexpectedRead,
			"expected", len(data),
			"written", n,
		)
	}
	return nil
}

// When we do a syscall we set opcodes to call a syscall and we put afterwards
// a breakpoint (see syscallInstruction). This function executes those opcodes
// and returns once we hit the breakpoint. During execution signal handlers
// of the trustee might run as well before the breakpoint is reached (this is
// why we use ptrace cont with a breakpoint and not ptrace single step).
func (p *Process) runToBreakpoint() errors.E {
	err := unix.PtraceCont(p.Pid, 0)
	if err != nil {
		return errors.WithMessage(err, "ptrace cont")
	}

	// 0 trap cause means a breakpoint or single stepping.
	return p.waitTrap(0)
}

func (p *Process) waitTrap(cause int) errors.E {
	for {
		var status unix.WaitStatus
		var err error
		for {
			_, err = unix.Wait4(p.Pid, &status, 0, nil)
			if err == nil || !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err != nil {
			return errors.WithMessage(err, "wait4")
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
			err := unix.PtraceCont(p.Pid, int(status.StopSignal()))
			if err != nil {
				errE := errors.WithMessage(err, "ptrace cont")
				errors.Details(errE)["stopSignal"] = int(status.StopSignal())
				return errE
			}
			continue
		}
		return errors.WithDetails(
			ErrUnexpectedWaitStatus,
			"exitStatus", status.ExitStatus(),
			"signal", status.Signal(),
			"stopSignal", status.StopSignal(),
			"trapCause", status.TrapCause(),
			"expectedTrapCause", cause,
		)
	}
}

// EqualFds returns true if both file descriptors point to the same underlying file.
func EqualFds(fd1, fd2 int) (bool, errors.E) {
	var stat1 unix.Stat_t
	err := unix.Fstat(fd1, &stat1)
	if err != nil {
		return false, errors.WithMessage(err, "fstat")
	}
	var stat2 unix.Stat_t
	err = unix.Fstat(fd2, &stat2)
	if err != nil {
		return false, errors.WithMessage(err, "fstat")
	}
	return stat1.Dev == stat2.Dev && stat1.Ino == stat2.Ino && stat1.Rdev == stat2.Rdev, nil
}
