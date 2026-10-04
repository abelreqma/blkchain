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
  pinned `package/cli.js` and a `node` file copied from
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

The browser container still needs network egress to the authorized target. The
Playwright route handler re-checks each browser request against scope, but it does
not pin the browser's socket to the IP address checked by secgate. A DNS rebinding
or a compromised browser could bypass that application-level check. Do not treat
route interception as an egress firewall; scope-enforcing, DNS-pinned egress remains
a required deployment control before using this tool with targets that can reach
operator or third-party networks.

Browser cookies and storage persist between browser actions while the task
executor is running, so a login can be followed by authenticated actions. The
context closes when that executor exits. The driver limits each browser action to
15 seconds and 100 browser requests, then truncates returned text at 200,000
characters. The text limit applies after the browser or HTTP client has buffered
the body; it does not cap response memory. API inputs are bounded to 1 MiB, and
active API redirects are not followed.

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
Run it in a provisioned environment to confirm the pins work end to end:

```
BLKCHAIN_PW_E2E=1 \
PLAYWRIGHT_DRIVER_PATH=<pinned local driver dir> \
BLKCHAIN_PLAYWRIGHT_CONTAINER=<running container name or ID> \
BLKCHAIN_PLAYWRIGHT_CDP=http://127.0.0.1:<port> \
go test -run TestWebPlaywrightE2E ./cli
```
