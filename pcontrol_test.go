package pcontrol

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMsghrd(t *testing.T) {
	t.Parallel()

	iov := []byte{1, 2, 3}
	control := []byte{4, 5, 6}
	offset, data, err := newMsghrd(42, iov, control)
	assert.NoError(t, err, "% -+#.1v", err)
	assert.Equal(t, uint64(22), offset)
	assert.Equal(t, []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x2a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2d, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0,
	}, data)
}

func TestSysGetpid(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("/bin/sleep", "infinity")
	e := cmd.Start()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	p := Process{
		Pid: cmd.Process.Pid,
	}
	err := p.Attach()
	require.NoError(t, err, "% -+#.1v", err)
	t.Cleanup(func() {
		assert.NoError(t, p.Detach(), "% -+#.1v", err)
	})

	pid, err := p.SysGetpid()
	require.NoError(t, err, "% -+#.1v", err)
	assert.Equal(t, cmd.Process.Pid, pid)
}

func ExampleProcess_SysGetpid() {
	cmd := exec.Command("/bin/sleep", "infinity")
	e := cmd.Start()
	if e != nil {
		panic(e)
	}
	defer cmd.Process.Wait() //nolint:errcheck
	defer cmd.Process.Kill() //nolint:errcheck

	p := Process{
		Pid: cmd.Process.Pid,
	}
	err := p.Attach()
	if err != nil {
		panic(err)
	}
	defer func() {
		err = p.Detach()
		if err != nil {
			panic(err)
		}
	}()

	pid, err := p.SysGetpid()
	if err != nil {
		panic(err)
	}
	fmt.Println(cmd.Process.Pid == pid)
	// Output: true
}

func startProcess(t *testing.T) (*exec.Cmd, *os.File, *os.File, *os.File, *os.File, *os.File, *os.File, *os.File) {
	t.Helper()

	stdin, stdinWriter, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = stdinWriter.Close()
	})

	stdout1, stdoutWriter1, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdout1.Close()
		_ = stdoutWriter1.Close()
	})

	stderr1, stderrWriter1, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stderr1.Close()
		_ = stderrWriter1.Close()
	})

	stdout2, stdoutWriter2, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdout2.Close()
		_ = stdoutWriter2.Close()
	})

	stderr2, stderrWriter2, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stderr2.Close()
		_ = stderrWriter2.Close()
	})

	cmd := exec.Command("/bin/bash", "-c", "read; echo end")
	cmd.Stdin = stdin
	cmd.Stdout = stdoutWriter1
	cmd.Stderr = stderrWriter1
	e = cmd.Start()
	require.NoError(t, e)

	return cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2
}

func TestGetFds(t *testing.T) {
	t.Parallel()

	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}

		_ = stdinWriter.Close()
		_ = stdoutWriter1.Close()
		_ = stderrWriter1.Close()
		_ = stdoutWriter2.Close()
		_ = stderrWriter2.Close()
		_ = stdout2.Close()
		_ = stderr2.Close()
	})

	p := Process{
		Pid: cmd.Process.Pid,
	}
	err := p.Attach()
	require.NoError(t, err, "% -+#.1v", err)
	t.Cleanup(func() {
		assert.NoError(t, p.Detach(), "% -+#.1v", err)
	})

	hostFds, err := p.GetFds([]int{1, 2})
	require.NoError(t, err, "% -+#.1v", err)
	require.Len(t, hostFds, 2)
	t.Cleanup(func() {
		for _, fd := range hostFds {
			os.NewFile(uintptr(fd), "fd").Close()
		}
	})

	equal, err := EqualFds(hostFds[0], int(stdoutWriter1.Fd()))
	assert.NoError(t, err, "% -+#.1v", err)
	assert.True(t, equal)

	equal, err = EqualFds(hostFds[1], int(stderrWriter1.Fd()))
	assert.NoError(t, err, "% -+#.1v", err)
	assert.True(t, equal)
}

func TestSetFd(t *testing.T) {
	t.Parallel()

	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}

		_ = stdinWriter.Close()
		_ = stdoutWriter1.Close()
		_ = stderrWriter1.Close()
		_ = stdoutWriter2.Close()
		_ = stderrWriter2.Close()
		_ = stdout2.Close()
		_ = stderr2.Close()
	})

	p := Process{
		Pid: cmd.Process.Pid,
	}
	err := p.Attach()
	require.NoError(t, err, "% -+#.1v", err)
	attached := true
	t.Cleanup(func() {
		if attached {
			assert.NoError(t, p.Detach(), "% -+#.1v", err)
		}
	})

	err = p.SetFd(int(stdoutWriter2.Fd()), 1)
	require.NoError(t, err, "% -+#.1v", err)
	err = p.SetFd(int(stderrWriter2.Fd()), 2)
	require.NoError(t, err, "% -+#.1v", err)

	require.NoError(t, p.Detach(), "% -+#.1v", err)
	attached = false

	_, _ = stdinWriter.WriteString("\n")

	_, _ = cmd.Process.Wait()
	waited = true

	_ = stdoutWriter1.Close()
	_ = stderrWriter1.Close()
	_ = stdoutWriter2.Close()
	_ = stderrWriter2.Close()

	sout, e := io.ReadAll(stdout2)
	require.NoError(t, e)

	serr, e := io.ReadAll(stderr2)
	require.NoError(t, e)

	assert.Equal(t, []byte("end\n"), sout)
	assert.Equal(t, []byte{}, serr)
}
