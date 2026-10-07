package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"blkchain/cli/internal/engagement"
)

// runStoreInteractive is a terminal navigator over the same store commands
// used by CLI, REPL, and TUI. It changes only the selected engagement.
func runStoreInteractive(ctx context.Context, in io.Reader, out io.Writer, selectedID, selectedWorkspace string) error {
	if selectedID != "" || selectedWorkspace != "" {
		ws, id, err := selectStoredWorkspace(ctx, selectedID, selectedWorkspace)
		if err != nil {
			return err
		}
		ws.Close()
		selectedID = id
	} else {
		items, err := listStoredEngagements(ctx)
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.Error == "" {
				selectedID = item.ID
				break
			}
		}
	}
	if _, err := fmt.Fprintf(out, "%s blk store\nlist / use ID / show / findings\nrecords / ask / add / review / help / quit\n", storeIcon("engagement")); err != nil {
		return err
	}
	if selectedID != "" {
		if _, err := fmt.Fprintf(out, "Selected: %s\n", terminalSafe(selectedID)); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(out, "No engagement selected. Use list, then use ID."); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := fmt.Fprint(out, "store> "); err != nil {
			return err
		}
		if !scanner.Scan() {
			return scanner.Err()
		}
		args, err := webArguments(scanner.Text())
		if err != nil {
			if _, writeErr := fmt.Fprintln(out, "Error: "+terminalSafe(err.Error())); writeErr != nil {
				return writeErr
			}
			continue
		}
		if len(args) == 0 {
			continue
		}
		verb := strings.ToLower(args[0])
		switch verb {
		case "quit", "exit":
			return nil
		case "help":
			_, err = fmt.Fprintln(out, "list       Find earlier engagements\nuse ID     Select an engagement\nshow       View surfaces and counts\nfindings   Review stored conclusions\nrecords    Read exact records by kind\nask        Ask the local model\nadd/review  Save operator decisions")
		case "use":
			if len(args) != 2 {
				err = errors.New("use requires one engagement id or workspace path")
				break
			}
			id, workspace := args[1], ""
			if strings.ContainsAny(id, `/\`) || strings.HasPrefix(id, ".") {
				workspace, id = id, ""
			}
			var wsID string
			var ws *engagement.Workspace
			ws, wsID, err = selectStoredWorkspace(ctx, id, workspace)
			if err == nil {
				ws.Close()
				selectedID, selectedWorkspace = wsID, ""
				if workspace != "" {
					selectedWorkspace = ws.Dir
				}
				_, err = fmt.Fprintf(out, "Selected: %s\n", terminalSafe(wsID))
			}
		case "list":
			err = runStoreTo(ctx, args, out, nil, "")
		case "show", "findings", "records", "ask", "add", "review":
			if selectedID == "" {
				err = errors.New("select an engagement with use ID")
				break
			}
			selector := []string{"--id", selectedID}
			if selectedWorkspace != "" {
				selector = []string{"--workspace", selectedWorkspace}
			}
			call := append([]string{verb}, selector...)
			call = append(call, args[1:]...)
			err = runStoreTo(ctx, call, out, nil, "")
		default:
			err = fmt.Errorf("unknown store action %q; type help", verb)
		}
		if err != nil {
			if _, writeErr := fmt.Fprintln(out, "Error: "+terminalSafe(err.Error())); writeErr != nil {
				return writeErr
			}
		}
	}
}
