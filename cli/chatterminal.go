package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const (
	chatTerminalMaxCommand = 4096
	chatTerminalMaxOutput  = 64 << 10
	chatTerminalMaxSeconds = 60
)

var chatDocker = runnerDocker

func chatContainerName(root string) string {
	digest := sha256.Sum256([]byte(root))
	return "blk-chat-" + hex.EncodeToString(digest[:12])
}

func chatRunnerImage(ctx context.Context) (string, error) {
	tag := defaultRunnerTag()
	image, err := chatDocker(ctx, nil, "image", "inspect", "--format", "{{.Id}}", tag)
	if err == nil {
		return image, nil
	}
	dir, err := os.MkdirTemp("", "blk-chat-image-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	entries, err := engageRunnerFiles.ReadDir("runner")
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		data, err := engageRunnerFiles.ReadFile("runner/" + entry.Name())
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o600); err != nil {
			return "", err
		}
	}
	build, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := chatDocker(build, nil, "build", "--tag", tag, dir); err != nil {
		return "", err
	}
	return chatDocker(ctx, nil, "image", "inspect", "--format", "{{.Id}}", tag)
}

func ensureChatContainer(ctx context.Context, root string) (string, error) {
	image, err := chatRunnerImage(ctx)
	if err != nil {
		return "", err
	}
	name := chatContainerName(root)
	label := "blkchain.chat.workspace=" + name
	format := `{{index .Config.Labels "blkchain.chat.workspace"}} {{.Image}} {{.State.Running}}`
	state, err := chatDocker(ctx, nil, "inspect", "--format", format, name)
	if err != nil {
		_, err = chatDocker(ctx, nil, "run", "-d", "--name", name, "--label", label,
			"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"--pids-limit", "128", "--memory", "2g", "--cpus", "2", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"--mount", "type=bind,src="+root+",dst=/work", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
			"--workdir", "/work", image, "sleep", "infinity")
		if err != nil {
			return "", err
		}
		state, err = chatDocker(ctx, nil, "inspect", "--format", format, name)
		if err != nil {
			return "", err
		}
	}
	fields := strings.Fields(state)
	if len(fields) != 3 || fields[0] != name || fields[1] != image {
		return "", fmt.Errorf("sandbox container identity changed")
	}
	if fields[2] != "true" {
		if _, err := chatDocker(ctx, nil, "start", name); err != nil {
			return "", err
		}
	}
	return name, nil
}

type chatTerminalArgs struct {
	Command        string `json:"command" desc:"shell command to run in the selected workspace"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" desc:"maximum runtime, 1 to 60 seconds"`
	Background     bool   `json:"background,omitempty" desc:"retain a sandbox process for process_manage"`
	PTY            bool   `json:"pty,omitempty" desc:"allocate a TTY for a foreground sandbox command"`
}

func chatTerminalCall(ctx context.Context, root, host string, in chatTerminalArgs) (string, error) {
	if strings.TrimSpace(in.Command) == "" || len(in.Command) > chatTerminalMaxCommand {
		return "", fmt.Errorf("command must be 1 to %d bytes", chatTerminalMaxCommand)
	}
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 30
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > chatTerminalMaxSeconds {
		return "", fmt.Errorf("timeout must be 1 to %d seconds", chatTerminalMaxSeconds)
	}
	if in.Background {
		if host == chatToolHostLocal || in.PTY {
			return "", fmt.Errorf("background processes require a non-PTY sandbox")
		}
		return startChatProcess(ctx, root, in.Command)
	}
	if in.PTY && host == chatToolHostLocal {
		return "", fmt.Errorf("PTY mode requires the sandbox")
	}
	name := ""
	if host != chatToolHostLocal {
		var err error
		name, err = ensureChatContainer(ctx, root)
		if err != nil {
			return "", err
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds+5)*time.Second)
	defer cancel()
	var output string
	var err error
	if host == chatToolHostLocal {
		cmd := exec.CommandContext(runCtx, "/bin/sh", "-lc", in.Command)
		cmd.Dir = root
		var data bytes.Buffer
		writer := &lockedWriter{w: &cappedWriter{cap: chatTerminalMaxOutput, buf: &data}}
		cmd.Stdout, cmd.Stderr = writer, writer
		cmd.WaitDelay = 2 * time.Second
		err = cmd.Run()
		output = data.String()
	} else {
		args := []string{"exec"}
		if in.PTY {
			args = append(args, "-t")
		}
		args = append(args, name, "/bin/sh", "-c", `ulimit -f 131072 || exit 1; exec timeout -s KILL "$1" /bin/sh -lc "$2"`, "sh", strconv.Itoa(in.TimeoutSeconds), in.Command)
		output, err = chatDocker(runCtx, nil, args...)
	}
	output = capRunes(output, chatTerminalMaxOutput)
	if err != nil {
		return fmt.Sprintf("exit: %s\n%s", terminalSafe(err.Error()), secgate.WrapUntrusted("terminal", output)), nil
	}
	return secgate.WrapUntrusted("terminal", output), nil
}

func newChatTerminalTool(root, host string) tooldef.Tool {
	location := "persistent isolated sandbox"
	if host == chatToolHostLocal {
		location = "operator-selected local working directory"
	}
	return newStoreTool("terminal", "Run a bounded shell command in the "+location+". Background processes are retained in the sandbox and managed with process_manage. The sandbox has no network access; use web tools for public research.", chatTerminalArgs{},
		func(ctx context.Context, args string) (string, error) {
			var in chatTerminalArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "terminal: invalid arguments", nil
			}
			out, err := chatTerminalCall(ctx, root, host, in)
			if err != nil {
				return "terminal: " + err.Error(), nil
			}
			return out, nil
		})
}
