# tstools_nic_monitor MCP Server

This is a small dependency-free Node MCP server for the `tstools_nic_monitor`
REST API. It speaks MCP over stdio and forwards requests to a running monitor
instance.

## Start `tstools_nic_monitor`

Enable the REST API when launching the monitor:

```sh
tstools_nic_monitor -i eth0 -M --rest-api-port 9601
```

If you are running from the local build tree, the binary may be under
`build/src/`.

## Launch The MCP Server

From the repository root:

```sh
NIC_MONITOR_REST_URL=http://127.0.0.1:9601 node ./mcp/nic-monitor/bin/nic-monitor-mcp.js
```

From this directory:

```sh
NIC_MONITOR_REST_URL=http://127.0.0.1:9601 node ./bin/nic-monitor-mcp.js
```

By default it calls:

```text
http://127.0.0.1:9601
```

Override that with `NIC_MONITOR_REST_URL`:

```sh
NIC_MONITOR_REST_URL=http://127.0.0.1:9601 node ./bin/nic-monitor-mcp.js
```

You can smoke-test the REST connection without starting an MCP client:

```sh
NIC_MONITOR_REST_URL=http://127.0.0.1:9601 npm run smoke
```

## Add To Codex

Add the MCP server definition to Codex:

```sh
codex mcp add nic-monitor --env NIC_MONITOR_REST_URL=http://127.0.0.1:9601 -- node /Users/stoth/GIT/ltntstools/mcp/nic-monitor/bin/nic-monitor-mcp.js
```

Confirm the definition:

```sh
codex mcp list
codex mcp get nic-monitor
```

Restart any already-running Codex session after adding the MCP definition.

## MCP Client Config Example

Use an absolute path in your MCP client config:

```json
{
  "mcpServers": {
    "nic-monitor": {
      "command": "node",
      "args": [
        "/Users/stoth/GIT/ltntstools/mcp/nic-monitor/bin/nic-monitor-mcp.js"
      ],
      "env": {
        "NIC_MONITOR_REST_URL": "http://127.0.0.1:9601"
      }
    }
  }
}
```

## Tools

- `get_transport_streams`: returns `/api/transport-streams`.
- `get_transport_pids`: returns `/api/transport-pids`.
- `get_stream_models`: returns `/api/stream-models`, matching the interactive
  `M` report.
- `get_stream_model`: returns one stream model by id, source, or destination.
- `get_stream_logs`: returns `/api/stream-logs`, matching the interactive `L`
  report.
- `get_stream_log`: returns one stream log by id, source, or destination.
- `get_iat_histograms`: returns `/api/iat-histograms`, matching the interactive
  `I` report.
- `get_iat_histogram`: returns one IAT histogram by id, source, or destination.
- `get_clock_reports`: returns `/api/clock-reports`, matching the interactive
  `C` report.
- `get_clock_report`: returns one clock report by id, source, or destination.
- `get_scte35_messages`: returns `/api/scte35`, with SCTE-35 messages retained
  during the last three hours.
- `get_scte35_messages_for_stream`: returns SCTE-35 history for one stream by
  id, source, or destination.
- `get_stream_summary`: finds one stream by id, source, or destination.
- `find_streams_with_errors`: filters streams with CC errors, IAT threshold
  hits, warning flags, or SRT retransmissions.
- `reset_statistics`: calls `POST /api/reset`.

## Resources

- `nic-monitor://transport-streams`
- `nic-monitor://transport-pids`
- `nic-monitor://stream-models`
- `nic-monitor://stream-logs`
- `nic-monitor://iat-histograms`
- `nic-monitor://clock-reports`
- `nic-monitor://scte35`
- `nic-monitor://openapi`
