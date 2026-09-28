package main

import (
	"fmt"
	"os"
)

// subcommands is the list offered by shell completion and help.
var subcommands = []string{
	"search", "ask", "open", "hermes", "up", "down", "status",
	"health", "doctor", "logs", "install", "version", "repl", "completion", "help",
}

// runCompletion prints a completion script for the named shell.
func runCompletion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("completion: specify a shell — bash or zsh")
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(os.Stdout, bashCompletion())
	case "zsh":
		fmt.Fprint(os.Stdout, zshCompletion())
	default:
		return fmt.Errorf("completion: unsupported shell %q (want bash or zsh)", args[0])
	}
	return nil
}

func cmdList() string {
	out := ""
	for i, c := range subcommands {
		if i > 0 {
			out += " "
		}
		out += c
	}
	return out
}

func bashCompletion() string {
	return `# blk bash completion — add to ~/.bashrc:  source <(blk completion bash)
_blk_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "` + cmdList() + `" -- "$cur") )
    return
  fi
  case "$prev" in
    completion) COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") ); return;;
    logs)       COMPREPLY=( $(compgen -W "api embed_server" -- "$cur") ); return;;
    search)     COMPREPLY=( $(compgen -W "--top-k --source --type --filter --json" -- "$cur") ); return;;
    ask)        COMPREPLY=( $(compgen -W "--sources --agent --json" -- "$cur") ); return;;
  esac
  COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -F _blk_complete blk
`
}

func zshCompletion() string {
	return `# blk zsh completion — add to ~/.zshrc:  source <(blk completion zsh)
_blk() {
  local -a cmds
  cmds=(` + cmdList() + `)
  if (( CURRENT == 2 )); then
    compadd -a cmds
    return
  fi
  case "${words[2]}" in
    completion) compadd bash zsh;;
    logs)       compadd api embed_server;;
    search)     compadd -- --top-k --source --type --filter --json;;
    ask)        compadd -- --sources --agent --json;;
    *)          _files;;
  esac
}
compdef _blk blk
`
}
