# korrel-cli

CLI that audits Model Context Protocol (MCP) servers for OAuth 2.1 and spec compliance.

## What it does

Given the URL of a remote MCP server, `korrel audit <url>` runs a series of probes against the authorization surface and produces:

- A Markdown report (`report.md`) with findings ordered by significance
- Raw HTTP evidence (`evidence/*.http`) for each request/response pair

The probes implement the methodology published at [korrel-dev/mcp-audits](https://github.com/korrel-dev/mcp-audits/blob/main/METHODOLOGY.md):

1. Discovery probe: 401 + `WWW-Authenticate` + Protected Resource Metadata link (RFC 9728)
2. Authorization server metadata (RFC 8414, §3.1 path-insertion form)
3. Client registration (RFC 7591 DCR, and Client ID Metadata Documents support)
4. PKCE enforcement (RFC 7636, S256 only, verifier validation)
5. Token hygiene (audience claim per RFC 8707, expiry, storage)
6. Ancillary checks (state parameter, HTTPS, security headers)

## Status

Early development. Probes 1-4 ship; probes 5-7 land on a weekly cadence aligned with the public audit series at [korrel-dev/mcp-audits](https://github.com/korrel-dev/mcp-audits). Per-probe status in [`docs/ROADMAP.md`](./docs/ROADMAP.md).

## Install

Not yet published to npm. For now, clone and run against source:

```
git clone https://github.com/korrel-dev/korrel-cli
cd korrel-cli
npm install
npx tsx src/cli.ts audit <url>
```

Requires Node 22 or later.

## Usage

```
korrel audit https://mcp.example.com/
```

Writes output to `./audits/<host>/`:

```
audits/mcp.example.com/
├── report.md
└── evidence/
    ├── 01-discovery.http
    └── ...
```

## License

MIT. See [`LICENSE`](./LICENSE).
