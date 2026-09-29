package main

import (
	"fmt"
	"os"
	"strings"
)

// commandNames lists every command in the registry, for shell completion.
func commandNames() []string {
	var names []string
	for _, c := range commandSpecs() {
		names = append(names, c.name)
	}
	return names
}

// runCompletion prints a completion script for the named shell.
func runCompletion(args []string) error {
	if len(args) != 1 {
		return missingArg("completion", "missing shell (bash or zsh)", "completion zsh")
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(os.Stdout, bashCompletion())
	case "zsh":
		fmt.Fprint(os.Stdout, zshCompletion())
	default:
		return usageErr(`completion: unsupported shell %q (want bash or zsh). Example: blk completion zsh. See "blk help completion".`, args[0])
	}
	return nil
}

// flagCases builds one case arm per command that has flags, in the shell's
// case syntax: "name) <action> <flags>;;". The flag lists come from the same
// flag sets the help uses, so completion cannot drift from the real flags.
func flagCases(action string) string {
	var b strings.Builder
	for _, c := range commandSpecs() {
		if c.flags == nil {
			continue
		}
		names := flagNames(commandFlagSet(c))
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(&b, "      %s) %s;;\n", c.name, fmt.Sprintf(action, strings.Join(names, " ")))
	}
	return b.String()
}

func bashCompletion() string {
	cmds := strings.Join(commandNames(), " ")
	return `# blk bash completion - add to ~/.bashrc:  source <(blk completion bash)
_blk_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "` + cmds + `" -- "$cur") )
    return
  fi
  if [[ "$cur" == -* ]]; then
    case "${COMP_WORDS[1]}" in
` + flagCases(`COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return`) + `    esac
  fi
  case "$prev" in
    help)       COMPREPLY=( $(compgen -W "` + cmds + `" -- "$cur") ); return;;
    completion) COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") ); return;;
    logs)       COMPREPLY=( $(compgen -W "api embed_server" -- "$cur") ); return;;
  esac
  COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -F _blk_complete blk
`
}

// zshEscape makes a description safe inside a single-quoted zsh _describe
// entry: a colon separates the name from the text, and a single quote ends the
// string.
func zshEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, ":", `\:`)
	return strings.ReplaceAll(s, "'", `'\''`)
}

func zshCompletion() string {
	var entries strings.Builder
	for _, c := range commandSpecs() {
		fmt.Fprintf(&entries, "    '%s:%s'\n", c.name, zshEscape(c.desc))
	}
	return `# blk zsh completion - add to ~/.zshrc:  source <(blk completion zsh)
_blk() {
  local -a cmds
  cmds=(
` + entries.String() + `  )
  if (( CURRENT == 2 )); then
    _describe -t commands 'blk command' cmds
    return
  fi
  if [[ "${words[CURRENT]}" == -* ]]; then
    case "${words[2]}" in
` + flagCases("compadd -- %s") + `    esac
    return
  fi
  case "${words[2]}" in
    help)       _describe -t commands 'blk command' cmds;;
    completion) compadd bash zsh;;
    logs)       compadd api embed_server;;
    *)          _files;;
  esac
}
compdef _blk blk
`
}
