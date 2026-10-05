package main

import (
	"context"
	"io"
	"sync"

	"blkchain/cli/internal/engagement"
)

type webFindingSinkKey struct{}
type webFindingMsg struct{ Data string }

func subscribeWebFindingOutput(ctx context.Context, store *engagement.Store, out io.Writer) func() {
	sink, ok := ctx.Value(webFindingSinkKey{}).(func([]byte) error)
	if !ok {
		var mu sync.Mutex
		sink = func(data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			_, err := out.Write(append(data, '\n'))
			return err
		}
	}
	return store.AddOnWebFinding(sink)
}
