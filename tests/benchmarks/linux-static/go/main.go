package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const payload = "hyperhub-static-go-probe"

func main() {
	if len(os.Args) == 4 && os.Args[1] == "--child" {
		port, err := strconv.Atoi(os.Args[3])
		if err != nil || port < 1 || port > 65535 {
			fatalf("invalid child port: %s", os.Args[3])
		}
		if err := runNetworkProbe(os.Args[2], port); err != nil {
			fatalf("child network probe failed: %v", err)
		}
		fmt.Println("static-go-child-ok")
		return
	}
	if len(os.Args) != 3 {
		fatalf("usage: %s host port", os.Args[0])
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port < 1 || port > 65535 {
		fatalf("invalid port: %s", os.Args[2])
	}
	if err := runRawSyscallProbe(); err != nil {
		fatalf("raw syscall probe failed: %v", err)
	}
	if err := runFileProbe(); err != nil {
		fatalf("file probe failed: %v", err)
	}
	if err := runNetworkProbe(os.Args[1], port); err != nil {
		fatalf("network probe failed: %v", err)
	}
	if err := runProcessProbe(os.Args[1], port); err != nil {
		fatalf("process probe failed: %v", err)
	}
	fmt.Println("static-go-probe-ok")
}

func runRawSyscallProbe() error {
	pid, _, errno := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if pid != uintptr(os.Getpid()) {
		return fmt.Errorf("getpid mismatch: raw=%d runtime=%d", pid, os.Getpid())
	}
	return nil
}

func runFileProbe() error {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("hyperhub-static-go-%d", os.Getpid()))
	renamed := path + "-renamed"
	defer os.Remove(path)
	defer os.Remove(renamed)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(payload); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return err
	}
	readback := make([]byte, len(payload))
	if _, err := io.ReadFull(file, readback); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if !bytes.Equal(readback, []byte(payload)) {
		return fmt.Errorf("readback mismatch")
	}
	if err := os.Rename(path, renamed); err != nil {
		return err
	}
	return os.Remove(renamed)
}

func runNetworkProbe(host string, port int) error {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write([]byte(payload)); err != nil {
		return err
	}
	readback := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, readback); err != nil {
		return err
	}
	if !bytes.Equal(readback, []byte(payload)) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func runProcessProbe(host string, port int) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	output, err := exec.Command(executable, "--child", host, strconv.Itoa(port)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("child failed: %w: %s", err, output)
	}
	if string(output) != "static-go-child-ok\n" {
		return fmt.Errorf("unexpected child output: %q", output)
	}
	return nil
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
