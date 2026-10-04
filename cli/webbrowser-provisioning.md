# Gated web browser + API tool: pinned, offline provisioning

The gated web tools (`web_browser`, `web_api`) drive a real browser and real
HTTP requests through the secgate Gate. Its driver (`cli/webplaywright.go`) is
pinned and NEVER downloads anything at runtime: it runs only against
operator-provisioned, pinned, integrity-verified artifacts. This document records
the exact pins and the provisioning wiring.

## Pinned artifacts

| Artifact | Pin | Notes |
|---|---|---|
| playwright-go (Go binding) | `github.com/mxschmitt/playwright-go v0.6201.1` | go.mod + go.sum (hashes recorded there). The Go module carries no binaries. |
| Playwright driver package | Playwright `1.62.1` (`playwright-core`, NO browsers) | Mounted read-only into the browser container. `playwright.Run` validates the driver version and refuses a mismatch. |
| Node launcher | `cli/playwright-container-node.sh`, SHA256 pinned in `cli/webplaywright.go` | Runs the driver with `docker exec` as UID 1000 inside the browser container. The launcher does not run Node on the operator host. |
| Browser image | DHI `dhi/playwright` pinned by digest `sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851` | Docker Hardened Image, debian-13, carries Playwright `1.63.0` browsers (chromium build 1243, node 24.21.0). Referenced BY DIGEST only, never the floating `:1` tag. |

Version note: the local client is 1.62.1 and the image browsers are 1.63.0. This
is intentional and validated: blkChain connects over CDP (Chrome DevTools
Protocol, tied to the Chromium build), not Playwright's own wire protocol, so the
client/server minor skew does not matter for the browser leg. A matching-version
pair is NOT required for CDP.

## Integrity

- The browser image is pinned and verified by its SHA256 manifest digest
  (`sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851`);
  provision it with `docker pull <image>@sha256:362a...` (or an offline load of that
  exact digest) and confirm `docker inspect` reports the same digest. Never pull the
  `:1` tag.
- The local driver is two pinned artifacts, verified before use:
  - `playwright-core@1.62.1` (npm): tarball
    `https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz`,
    npm integrity
    `sha512-wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw==`
    (sha1 `120f67a19181bfd183c60fa903c0d99330b56785`).
- Node.js runs inside the pinned browser image. The operator host needs the Docker
  CLI and the pinned Playwright package, not a local Node runtime.

## No auto-fetch (enforced)

blkChain never calls `playwright.Install` or `DownloadDriver` on any path. A source
guard test (`TestWebDriverNeverCallsInstall`) fails the build if a production file
references either. A missing or mismatched local driver makes `playwright.Run`
return an error, not trigger a download. With nothing provisioned the tool fails
closed.

## Wiring

The driver reads these environment values and fails closed without them:

- `PLAYWRIGHT_DRIVER_PATH` - the driver package directory. It must contain the
  pinned `playwright-core-1.62.1.tgz`, its extracted `package/cli.js`, and a `node` file copied from
  `cli/playwright-container-node.sh`. blkChain checks the launcher's SHA256.
- `BLKCHAIN_PLAYWRIGHT_CONTAINER` - the name or ID of the running pinned DHI
  container. The container must run as UID 1000 and mount
  `$PLAYWRIGHT_DRIVER_PATH/package` read-only at
  `/opt/blkchain-playwright/package`.
- `BLKCHAIN_PLAYWRIGHT_CDP` - the browser's loopback CDP endpoint as seen from
  inside the container, normally `http://127.0.0.1:9222`. The Node driver runs
  inside that container, so the endpoint is not published to the host.
- `BLKCHAIN_DOCKER_BIN` - optional absolute path to the Docker CLI; defaults to
  `docker` from `PATH`.

## Isolating the browser driver

Copy the checked-in launcher to `PLAYWRIGHT_DRIVER_PATH/node`, make it executable,
and mount only the `package` directory read-only into the browser container. Do not
mount the Docker socket, the operator home directory, credentials, or the repository.
Do not use host networking or privileged mode. Keep CDP bound to container loopback.
The DHI image contains the Node runtime and browser. The Go binding starts the
launcher on the host, and the launcher executes the pinned driver inside the
container. Browser-controlled CDP data therefore reaches the Go process, but it
does not reach a host Node process.

The container must use `--network none`. It has no direct target egress. Every
browser request, including worker traffic, crosses a proxy bound to container
loopback. Its HTTP and WebSocket adapters call the Go broker after request policy,
DNS resolution, address validation, and socket pinning. Redirects repeat the
checks; WebSocket handshakes reject redirects. Configured role credentials remain
bound to their exact origin. Browser-generated writes and outbound WebSocket
messages require an armed task and the unattended action policy.

The local proxy uses a fresh ECDSA certificate in memory for HTTPS/WSS tunnels.
Chromium accepts that local relay certificate, including service-worker fetches.
The Go broker independently verifies the target certificate and hostname with
TLS 1.2 or later. Target certificate failures still deny acquisition. The proxy
has no target socket access; only Go can connect to validated targets. Its Node
runtime and WebSocket server come from the verified driver and pinned image.

WebSocket messages are capped at 256 KiB each, 250 per connection, and 16
connections per proxy. HTTP and socket transfers share the broker's 64 MiB wire
and accepted-byte limits. Cancellation closes sockets and the proxy process;
accepted queued evidence is flushed before collection returns. Worker/CDP cache
failures and stream/window limits remain explicit coverage records.

The Go WebSocket client is Gorilla v1.5.3 at commit
`ce903f6d1d961af3a8602f2842c8b1c3fca58c4d`, verified by the `go.sum` hash
`h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=`.

The container validator requires the pinned image, `--user 1000:1000`, a read-only
root filesystem, 128 MiB to 2 GiB memory, at most four CPUs, at most 512 processes,
`--cap-drop ALL`, and `--security-opt no-new-privileges`. Only the read-only driver
package bind and temporary filesystem mounts are allowed. Do not publish CDP.
The pinned image's `/usr/lib/node_modules` path is permitted; alternate Node
preloads and module paths are rejected. Every installed driver file must match
the verified npm tarball. Extra files and symlinks are rejected.

An Apple Silicon fixture container can be provisioned explicitly with:

```sh
export PLAYWRIGHT_DRIVER_PATH=/absolute/path/to/verified-driver
export BLKCHAIN_PLAYWRIGHT_CONTAINER=blk-web-browser
export BLKCHAIN_PLAYWRIGHT_CDP=http://127.0.0.1:9222
cp cli/playwright-container-node.sh "$PLAYWRIGHT_DRIVER_PATH/node"
chmod 700 "$PLAYWRIGHT_DRIVER_PATH/node"
docker run -d --name "$BLKCHAIN_PLAYWRIGHT_CONTAINER" \
  --network none --user 1000:1000 --read-only --memory 1g --cpus 2 \
  --pids-limit 256 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --mount "type=bind,src=$PLAYWRIGHT_DRIVER_PATH/package,dst=/opt/blkchain-playwright/package,readonly" \
  --entrypoint /ms-playwright/chromium-1243/chrome-linux-arm64/chrome \
  dhi.io/playwright@sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851 \
  --headless=new --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir=/tmp/blk-profile about:blank
```

Verify the tarball with the SHA512 above before extracting it. Keep the tarball
beside the extracted package. The constructor repeats the integrity checks;
provisioning does not replace runtime validation. The browser path above applies
to the pinned ARM image. Use the corresponding path from the pinned image on
another architecture.

Cookies and storage persist within one isolated task or supplied role. Contexts
close when the executor or collection job exits. API calls share those cookies
through the Go broker. A restart creates a fresh context from the supplied
session configuration. No path opens the operator's personal browser profile.

Wire responses and decompressed bodies each have a 4 MiB limit. A broker permits
500 requests and 64 MiB aggregate transfer and accepted-body budgets. Request
bodies have a 1 MiB limit. Oversized, interrupted, or unsupported bodies produce
incomplete artifacts and coverage gaps. Runtime DOM previews have a 200,000
character bound; model previews strip scripts and input values and have a
16,384 character bound. Exact accepted source is stored separately. See
[web-analysis.md](web-analysis.md) for storage, parser, and job limits.

In Auto mode, `.blkchain/config.yaml` must explicitly allow the synthetic action
labels to run without confirmation. Add only the actions needed by the engagement:

```yaml
allowed_binaries:
  - web-browser:navigate
  - web-browser:active
  - web-api:GET
  - web-api:POST
```

Active actions still require an armed task and an in-scope target. URL userinfo is
rejected; supply API credentials through headers or browser credentials through
in-scope form fields.

## Verifying end to end

`cli/webplaywright_e2e_test.go` (`TestWebPlaywrightE2E`, gated by
`BLKCHAIN_PW_E2E=1`) drives the real production path - `newWebPlaywrightDriver` ->
`ConnectOverCDP` -> `DoBrowser` / `DoAPIRequest` - against a provisioned container.
It checks dynamic, inline, lazy, and frame scripts; denied subresources and
unarmed writes; exact source storage; authorized active requests; and cookies.
Set `BLKCHAIN_WEB_LLM_E2E=1` to also test the live local LLM inspection loop.
Run from `cli/` in a provisioned environment:

```
BLKCHAIN_PW_E2E=1 \
PLAYWRIGHT_DRIVER_PATH=<pinned local driver dir> \
BLKCHAIN_PLAYWRIGHT_CONTAINER=<running container name or ID> \
BLKCHAIN_PLAYWRIGHT_CDP=http://127.0.0.1:<port> \
go test -run TestWebPlaywrightE2E -count=1 -timeout 120s .
```
