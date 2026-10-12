package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func rawSessionArgs(name string, args []string) (string, int, error) {
	fs := newFlagSet(name)
	var dir, portText string
	fs.StringVar(&dir, "workspace", "", "engagement workspace directory")
	fs.StringVar(&portText, "port", "0", "loopback listener port (0 chooses one)")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "port": true})); err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if dir == "" || len(fs.Args()) != 0 || err != nil || port < 0 || port > 65535 {
		return "", 0, usageErr("%s requires --workspace DIR [--port 0-65535]", name)
	}
	return dir, port, nil
}

func runEngageSessionDaemon(args []string) error {
	dir, port, err := rawSessionArgs("engage sessiond", args)
	if err != nil {
		return err
	}
	return runRawSessionDaemon(context.Background(), dir, port)
}

func runEngageListenShell(args []string) error {
	dir, port, err := rawSessionArgs("engage listen-shell", args)
	if err != nil {
		return err
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(dir, "run.json"), &metadata); err != nil {
		return err
	}
	if metadata.Status == "complete" {
		return errors.New("completed engagement cannot start a raw session listener")
	}
	if existing, err := readRawSessionRecord(dir); err != nil {
		return err
	} else if existing != nil {
		return errors.New("raw session record already exists; close the prior listener first")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(binary, "engage", "sessiond", "--workspace", dir, "--port", strconv.Itoa(port))
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		record, readErr := readRawSessionRecord(dir)
		if readErr == nil && record != nil && record.PID == cmd.Process.Pid && record.PolicyHash == metadata.PolicyHash {
			if _, statusErr := rawBrokerStatus(context.Background(), record.ControlAddress, record.Token); statusErr == nil {
				_ = cmd.Process.Release()
				fmt.Fprintln(os.Stdout, record.ShellAddress)
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return errors.New("raw session listener did not become ready")
}

func runEngageCloseShell(args []string) error {
	fs := newFlagSet("engage close-shell")
	var dir string
	fs.StringVar(&dir, "workspace", "", "engagement workspace directory")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true})); err != nil {
		return err
	}
	if dir == "" || len(fs.Args()) != 0 {
		return usageErr("engage close-shell requires --workspace DIR")
	}
	record, err := readRawSessionRecord(dir)
	if err != nil {
		return err
	}
	if record == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rawBrokerClose(ctx, record.ControlAddress, record.Token); err != nil {
		lock, lockErr := rawSessionLock(dir)
		if lockErr != nil {
			return err
		}
		defer lock.Close()
		current, readErr := readRawSessionRecord(dir)
		if readErr != nil {
			return readErr
		}
		if current != nil && current.PID == record.PID && current.Token == record.Token {
			return os.Remove(rawSessionRecordPath(dir))
		}
		return nil
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, err := readRawSessionRecord(dir)
		if err == nil && current == nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("raw session listener did not close")
}
