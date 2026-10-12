package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type rawSessionRecord struct {
	PolicyHash     string `json:"policy_hash"`
	ShellAddress   string `json:"shell_address"`
	ControlAddress string `json:"control_address"`
	Token          string `json:"token"`
	PID            int    `json:"pid"`
	ExpiresAt      string `json:"expires_at"`
}

func rawSessionRecordPath(dir string) string {
	return filepath.Join(dir, "raw-session.json")
}

func validLoopbackAddress(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	return err == nil && portErr == nil && host == "127.0.0.1" && port >= 1 && port <= 65535
}

func readRawSessionRecord(dir string) (*rawSessionRecord, error) {
	f, err := os.OpenFile(rawSessionRecordPath(dir), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("raw session record must be a private regular file under 4 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("raw session record exceeds limit")
	}
	if err := uniqueJSONFields(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record rawSessionRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("invalid raw session record: %w", err)
	}
	if len(record.PolicyHash) != 64 || len(record.Token) != 64 || record.PID < 1 ||
		!validLoopbackAddress(record.ShellAddress) || !validLoopbackAddress(record.ControlAddress) {
		return nil, errors.New("invalid raw session record fields")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.ExpiresAt); err != nil {
		return nil, errors.New("invalid raw session expiration")
	}
	return &record, nil
}

func rawSessionLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "raw-session.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("raw session lock must be a regular file")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("raw session broker already running")
	}
	return f, nil
}

func runRawSessionDaemon(parent context.Context, dir string, port int) error {
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(dir, "run.json"), &metadata); err != nil {
		return err
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: metadata.RoE}, metadata.ProjectDir, nil)
	if err != nil {
		return err
	}
	if roe.Policy.Hash != metadata.PolicyHash || !roe.Policy.Allows("command") {
		return errors.New("raw session requires the checkpoint's command-authorized RoE")
	}
	if metadata.Status == "complete" {
		return errors.New("completed engagement cannot retain a raw session")
	}
	if err := verifyEngagePolicy(filepath.Join(dir, "policy.json"), roe.Policy.Canonical); err != nil {
		return err
	}
	started, err := time.Parse(time.RFC3339Nano, metadata.Started)
	if err != nil {
		return err
	}
	expires := started.Add(time.Duration(roe.Policy.WallSeconds) * time.Second)
	if !time.Now().Before(expires) {
		return errors.New("raw session engagement budget expired")
	}
	lock, err := rawSessionLock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if existing, err := readRawSessionRecord(dir); err != nil {
		return err
	} else if existing != nil {
		return errors.New("raw session record already exists")
	}
	ctx, cancel := context.WithDeadline(parent, expires)
	defer cancel()
	broker, err := newRawBroker(ctx, port, expires)
	if err != nil {
		return err
	}
	defer broker.Close()
	record := rawSessionRecord{PolicyHash: roe.Policy.Hash, ShellAddress: broker.ShellAddr(),
		ControlAddress: broker.ControlAddr(), Token: broker.Token(), PID: os.Getpid(), ExpiresAt: expires.UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := atomicWrite(rawSessionRecordPath(dir), data); err != nil {
		return err
	}
	defer func() {
		if current, err := readRawSessionRecord(dir); err == nil && current != nil && current.PID == record.PID && current.Token == record.Token {
			_ = os.Remove(rawSessionRecordPath(dir))
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-broker.Done():
		return nil
	}
}
