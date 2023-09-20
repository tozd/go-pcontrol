//go:build linux && amd64
// +build linux,amd64

package pcontrol

import (
	"encoding/binary"

	"gitlab.com/tozd/go/errors"
	"golang.org/x/sys/unix"
)

var nativeEndian = binary.LittleEndian //nolint:gochecknoglobals

// Call a syscall and a breakpoint. We do not use ptrace single step but ptrace cont
// until a breakpoint so that it is easier to allow signal handlers in process to run.
var syscallInstruction = [...]byte{0x0F, 0x05, 0xCC} //nolint:gochecknoglobals

type processRegs unix.PtraceRegs

func getProcessRegs(pid int) (processRegs, errors.E) {
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(pid, &regs)
	if err != nil {
		return processRegs{}, errors.WithMessage(err, "ptrace get regs") //nolint:exhaustruct
	}
	return processRegs(regs), nil
}

func setProcessRegs(pid int, regs *processRegs) errors.E {
	err := unix.PtraceSetRegs(pid, (*unix.PtraceRegs)(regs))
	return errors.WithMessage(err, "ptrace set regs")
}

func newSyscallRegs(originalRegs *processRegs, ip uint64, call int, arg0, arg1, arg2, arg3, arg4, arg5 uint64) processRegs {
	newRegs := *originalRegs
	(*unix.PtraceRegs)(&newRegs).SetPC(ip)
	newRegs.Rdi = arg0
	newRegs.Rsi = arg1
	newRegs.Rdx = arg2
	newRegs.R10 = arg3
	newRegs.R8 = arg4
	newRegs.R9 = arg5
	newRegs.Rax = uint64(call)
	return newRegs
}

func getSyscallResultReg(regs *processRegs) uint64 {
	return regs.Rax
}

func getProcessPC(regs *processRegs) uint64 {
	return (*unix.PtraceRegs)(regs).PC()
}
