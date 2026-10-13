package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const chatProcessDir = ".blk-processes"

var chatProcessIDPattern = regexp.MustCompile(`^proc_[0-9a-f]{16}$`)

func startChatProcess(ctx context.Context, root, command string) (string, error) {
	dir := filepath.Join(root, chatProcessDir)
	if err := privateDir(dir); err != nil {
		return "", err
	}
	name, err := ensureChatContainer(ctx, root)
	if err != nil {
		return "", err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := fmt.Sprintf("proc_%x", random)
	script := `dir=/work/.blk-processes; id="$1"; command="$2"; ulimit -f 131072 || exit 1; mkfifo "$dir/$id.in" || exit 1; exec 3<>"$dir/$id.in"; setsid timeout -s KILL 3600 /bin/sh -lc "$command" <&3 >"$dir/$id.log" 2>&1 & child=$!; printf '%s\n' "$child" >"$dir/$id.pid"; wait "$child"; printf '%s\n' "$?" >"$dir/$id.exit"`
	if _, err := chatDocker(ctx, nil, "exec", "-d", name, "/bin/sh", "-c", script, "sh", id, command); err != nil {
		return "", err
	}
	pidPath := filepath.Join(dir, id+".pid")
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(pidPath); err == nil {
			return "background process " + id + " started", nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("background process did not start")
}

type chatProcessArgs struct {
	Action         string `json:"action" desc:"list, poll, log, wait, write, or kill"`
	SessionID      string `json:"session_id,omitempty" desc:"process handle returned by terminal"`
	Data           string `json:"data,omitempty" desc:"input bytes for write, at most 4096"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" desc:"wait timeout, at most 60 seconds"`
}

func chatProcessFile(root, id, suffix string) string {
	return filepath.Join(root, chatProcessDir, id+suffix)
}

func chatProcessStatus(ctx context.Context, root, id string) string {
	data, err := os.ReadFile(chatProcessFile(root, id, ".exit"))
	if err == nil {
		return "exited with code " + strings.TrimSpace(string(data))
	}
	pid, err := os.ReadFile(chatProcessFile(root, id, ".pid"))
	if os.IsNotExist(err) {
		return "missing"
	}
	if err != nil {
		return "status unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = chatDocker(probe, nil, "exec", chatContainerName(root), "/bin/sh", "-c", `kill -0 "$1"`, "sh", strings.TrimSpace(string(pid)))
	if err == nil {
		return "running"
	}
	time.Sleep(50 * time.Millisecond)
	if data, err := os.ReadFile(chatProcessFile(root, id, ".exit")); err == nil {
		return "exited with code " + strings.TrimSpace(string(data))
	}
	return "lost without an exit receipt"
}

func chatProcessLog(root, id string) (string, error) {
	f, err := os.Open(chatProcessFile(root, id, ".log"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > chatTerminalMaxOutput {
		if _, err := f.Seek(-chatTerminalMaxOutput, io.SeekEnd); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, chatTerminalMaxOutput))
	if err != nil {
		return "", err
	}
	return secgate.WrapUntrusted("terminal", string(data)), nil
}

func chatProcessCall(ctx context.Context, root string, in chatProcessArgs) (string, error) {
	if in.Action == "list" {
		dir, err := os.Open(filepath.Join(root, chatProcessDir))
		if os.IsNotExist(err) {
			return "no background processes", nil
		}
		if err != nil {
			return "", err
		}
		defer dir.Close()
		entries, err := dir.ReadDir(256)
		if err != nil && err != io.EOF {
			return "", err
		}
		var out strings.Builder
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".pid") {
				id := strings.TrimSuffix(entry.Name(), ".pid")
				if chatProcessIDPattern.MatchString(id) {
					fmt.Fprintf(&out, "%s %s\n", id, chatProcessStatus(ctx, root, id))
				}
			}
		}
		if out.Len() == 0 {
			return "no background processes", nil
		}
		return capRunes(out.String(), 4096), nil
	}
	if !chatProcessIDPattern.MatchString(in.SessionID) {
		return "", fmt.Errorf("invalid process handle")
	}
	switch in.Action {
	case "poll":
		return in.SessionID + " " + chatProcessStatus(ctx, root, in.SessionID), nil
	case "log":
		return chatProcessLog(root, in.SessionID)
	case "wait":
		if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 60 {
			in.TimeoutSeconds = 30
		}
		timer := time.NewTimer(time.Duration(in.TimeoutSeconds) * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			status := chatProcessStatus(ctx, root, in.SessionID)
			if status != "running" {
				return in.SessionID + " " + status, nil
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-timer.C:
				return in.SessionID + " still running", nil
			case <-tick.C:
			}
		}
	case "write":
		if len(in.Data) == 0 || len(in.Data) > 4096 || chatProcessStatus(ctx, root, in.SessionID) != "running" {
			return "", fmt.Errorf("write requires a running process and 1 to 4096 bytes")
		}
		name, err := ensureChatContainer(ctx, root)
		if err != nil {
			return "", err
		}
		fifo := "/work/.blk-processes/" + in.SessionID + ".in"
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err = chatDocker(writeCtx, []byte(in.Data), "exec", "-i", name, "/bin/sh", "-c", `cat > "$1"`, "sh", fifo)
		if err != nil {
			return "", err
		}
		return "input sent", nil
	case "kill":
		pidBytes, err := os.ReadFile(chatProcessFile(root, in.SessionID, ".pid"))
		if err != nil {
			return "", err
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil || pid < 2 {
			return "", fmt.Errorf("invalid retained process PID")
		}
		name, err := ensureChatContainer(ctx, root)
		if err != nil {
			return "", err
		}
		_, err = chatDocker(ctx, nil, "exec", name, "/bin/sh", "-c", `kill -TERM "-$1"`, "sh", strconv.Itoa(pid))
		if err != nil {
			return "", err
		}
		return "termination requested", nil
	default:
		return "", fmt.Errorf("unknown process action")
	}
}

func newChatProcessTool(root string) tooldef.Tool {
	return newStoreTool("process_manage", "Manage retained sandbox terminal processes by handle: list, poll, log, wait, write, or kill.", chatProcessArgs{},
		func(ctx context.Context, args string) (string, error) {
			var in chatProcessArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "process_manage: invalid arguments", nil
			}
			out, err := chatProcessCall(ctx, root, in)
			if err != nil {
				return "process_manage: " + err.Error(), nil
			}
			return out, nil
		})
}
