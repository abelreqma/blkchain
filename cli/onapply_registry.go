package main

import "blkchain/cli/internal/engagement"

var onApplyListeners []func(rev int64, e engagement.Engagement)

func registerOnApply(fn func(rev int64, e engagement.Engagement)) {
	onApplyListeners = append(onApplyListeners, fn)
}
