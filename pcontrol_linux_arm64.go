//go:build linux && arm64
// +build linux,arm64

package pcontrol

import (
	"encoding/binary"

	"gitlab.com/tozd/go/errors"
	"golang.org/x/sys/unix"
)

var nativeEndian = binary.LittleEndian

// Call a syscall and a breakpoint. We do not use ptrace single step but ptrace cont
// until a breakpoint so that it is easier to allow signal handlers in process to run.
var syscallInstruction = [...]byte{0xEF, 0x00, 0x00, 0x00, 0xE7, 0xF0, 0x01, 0xF0}

type processRegs unix.PtraceRegs

func getProcessRegs(pid int) (processRegs, errors.E) {
	var regs unix.PtraceRegs
	err := errors.WithStack(unix.PtraceGetRegs(pid, &regs))
	if err != nil {
		return processRegs{}, errors.Errorf("ptrace getregs: %w", err)
	}
	return processRegs(regs), nil
}

func setProcessRegs(pid int, regs *processRegs) errors.E {
	err := errors.WithStack(unix.PtraceSetRegs(pid, (*unix.PtraceRegs)(regs)))
	if err != nil {
		return errors.Errorf("ptrace setregs: %w", err)
	}
	return nil
}

func newSyscallRegs(originalRegs *processRegs, ip uint64, call int, arg0, arg1, arg2, arg3, arg4, arg5 uint64) processRegs {
	newRegs := *originalRegs
	(*unix.PtraceRegs)(&newRegs).SetPC(ip)
	newRegs.Regs[0] = arg0
	newRegs.Regs[1] = arg1
	newRegs.Regs[2] = arg2
	newRegs.Regs[3] = arg3
	newRegs.Regs[4] = arg4
	newRegs.Regs[5] = arg5
	newRegs.Regs[8] = uint64(call)
	return newRegs
}

func getSyscallResultReg(regs *processRegs) uint64 {
	return regs.Regs[0]
}

func getProcessPC(regs *processRegs) uint64 {
	return (*unix.PtraceRegs)(regs).PC()
}
