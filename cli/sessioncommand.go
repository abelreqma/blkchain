package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

type sessionCommand struct {
	text  string
	start []byte
	end   []byte
}

func newSessionCommand(stages [][]string) (sessionCommand, error) {
	if len(stages) == 0 || len(stages) > 3 {
		return sessionCommand{}, errors.New("invalid session command")
	}
	argBytes := 0
	commands := make([]string, 0, len(stages))
	for _, args := range stages {
		if len(args) == 0 || len(args) > 1024 {
			return sessionCommand{}, errors.New("invalid session stage")
		}
		for _, arg := range args {
			argBytes += len(arg)
			if strings.ContainsRune(arg, 0) || argBytes > 65536 {
				return sessionCommand{}, errors.New("invalid session argument")
			}
		}
		commands = append(commands, shellQuoteArgv(args))
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return sessionCommand{}, err
	}
	id := hex.EncodeToString(nonce[:])
	return sessionCommand{
		text:  "printf '\\036" + id + ":START\\036'; " + strings.Join(commands, " | ") + "; _blk_rc=$?; printf '\\036" + id + ":END:%d\\036' \"$_blk_rc\"\n",
		start: []byte("\x1e" + id + ":START\x1e"),
		end:   []byte("\x1e" + id + ":END:"),
	}, nil
}

func (c sessionCommand) parse(data []byte, limit int) (rawSessionResponse, bool, error) {
	begin := bytes.Index(data, c.start)
	if begin < 0 {
		return rawSessionResponse{}, false, nil
	}
	body := data[begin+len(c.start):]
	finish := bytes.Index(body, c.end)
	if finish < 0 {
		return rawSessionResponse{}, false, nil
	}
	code := body[finish+len(c.end):]
	stop := bytes.IndexByte(code, '\x1e')
	if stop < 0 {
		return rawSessionResponse{}, false, nil
	}
	exitCode, err := strconv.Atoi(string(code[:stop]))
	if err != nil || exitCode < 0 || exitCode > 255 || finish > limit {
		return rawSessionResponse{}, true, errors.New("invalid session receipt")
	}
	return rawSessionResponse{Output: string(body[:finish]), ExitCode: exitCode}, true, nil
}
