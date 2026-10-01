package main

import "blkchain/cli/internal/engagement"

var webLadder = reconLadder{
	{Index: 0, Name: "liveness-fingerprint", Dimensions: []string{"liveness", "server", "tls"}},
	{Index: 1, Name: "content-discovery", Dimensions: []string{"content", "paths"}},
	{Index: 2, Name: "param-discovery", Dimensions: []string{"params", "endpoints"}},
	{Index: 3, Name: "finding-driven-probes", Dimensions: []string{"probes"}},
}

type webExecutor struct {
	genericExecutor
}

func init() {
	registerExecutor(engagement.SurfaceWeb, func(d engageDeps) surfaceExecutor {
		return webExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceWeb, webLadder)
}
