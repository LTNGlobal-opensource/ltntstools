#!/usr/bin/env node

const DEFAULT_BASE_URL = "http://127.0.0.1:9601";
const SERVER_NAME = "ltntstools-nic-monitor-mcp";
const SERVER_VERSION = "0.1.0";

const baseUrl = normalizeBaseUrl(process.env.NIC_MONITOR_REST_URL || DEFAULT_BASE_URL);

const tools = [
  {
    name: "get_transport_streams",
    description: "Return the current stream summary from tstools_nic_monitor, including warning flag definitions and interpreted warningFlags per stream.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_transport_pids",
    description: "Return current per-PID statistics grouped by stream.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_stream_models",
    description: "Return PAT/PMT service information for all streams, matching the interactive M report.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_stream_model",
    description: "Return the PAT/PMT service model for one stream by id, source, or destination.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address, for example 227.1.1.1:4001."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "get_stream_logs",
    description: "Return stream log lines for all streams, matching the interactive L report.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_stream_log",
    description: "Return the stream log for one stream by id, source, or destination.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "get_iat_histograms",
    description: "Return IAT histogram reports for all streams, matching the interactive I report.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_iat_histogram",
    description: "Return the IAT histogram report for one stream by id, source, or destination.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "get_clock_reports",
    description: "Return PCR clock reports for all streams, matching the interactive C report.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_clock_report",
    description: "Return the PCR clock report for one stream by id, source, or destination.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "get_scte35_messages",
    description: "Return SCTE-35 messages retained during the last three hours for all streams.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: "get_scte35_messages_for_stream",
    description: "Return SCTE-35 messages retained during the last three hours for one stream by id, source, or destination.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "get_stream_summary",
    description: "Return one stream by id, source, or destination, including warning flag definitions and interpreted warningFlags. Optionally include per-PID and UI report data.",
    inputSchema: {
      type: "object",
      properties: {
        stream: {
          type: "string",
          description: "Stream id, source address, or destination address, for example 227.1.1.1:4001."
        },
        includePids: {
          type: "boolean",
          description: "When true, include per-PID statistics for the matched stream."
        },
        includeModel: {
          type: "boolean",
          description: "When true, include the stream model report."
        },
        includeLog: {
          type: "boolean",
          description: "When true, include the stream log report."
        },
        includeIat: {
          type: "boolean",
          description: "When true, include the IAT histogram report."
        },
        includeClock: {
          type: "boolean",
          description: "When true, include the PCR clock report."
        },
        includeScte35: {
          type: "boolean",
          description: "When true, include SCTE-35 messages retained during the last three hours."
        }
      },
      required: ["stream"],
      additionalProperties: false
    }
  },
  {
    name: "find_streams_with_errors",
    description: "Find streams with CC errors, high IAT, warning flags, or SRT retransmissions. Results include warning flag definitions and interpreted warningFlags per stream.",
    inputSchema: {
      type: "object",
      properties: {
        minCcErrors: {
          type: "integer",
          minimum: 0,
          description: "Minimum CC error count. Defaults to 1."
        },
        iatThresholdMs: {
          type: "integer",
          minimum: 0,
          description: "Optional IAT high-water threshold in milliseconds."
        },
        includeWarnings: {
          type: "boolean",
          description: "Include streams with non-empty warning flags. Defaults to true."
        },
        includeSrtRetransmissions: {
          type: "boolean",
          description: "Include streams with SRT retransmissions. Defaults to true."
        }
      },
      additionalProperties: false
    }
  },
  {
    name: "reset_statistics",
    description: "Reset nic_monitor statistics, matching the interactive r command.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  }
];

const resources = [
  {
    uri: "nic-monitor://transport-streams",
    name: "Transport streams",
    description: "Current stream summary from tstools_nic_monitor, including warning flag definitions.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://transport-pids",
    name: "Transport PIDs",
    description: "Current per-PID statistics grouped by stream.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://stream-models",
    name: "Stream models",
    description: "PAT/PMT service information grouped by stream.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://stream-logs",
    name: "Stream logs",
    description: "Per-stream log lines.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://iat-histograms",
    name: "IAT histograms",
    description: "Per-stream IAT histogram reports.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://clock-reports",
    name: "Clock reports",
    description: "Per-stream PCR clock reports.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://scte35",
    name: "SCTE-35",
    description: "Per-stream SCTE-35 messages retained during the last three hours.",
    mimeType: "application/json"
  },
  {
    uri: "nic-monitor://openapi",
    name: "OpenAPI schema",
    description: "OpenAPI document exposed by tstools_nic_monitor.",
    mimeType: "application/json"
  }
];

if (process.argv.includes("--smoke-test")) {
  await smokeTest();
  process.exit(0);
}

let preferredFrame = "newline";
let input = Buffer.alloc(0);
let activeRequests = 0;
let stdinEnded = false;

process.stdin.on("data", chunk => {
  input = Buffer.concat([input, chunk]);
  void drainInput();
});

process.stdin.on("end", () => {
  stdinEnded = true;
  maybeExit();
});

process.stdin.resume();

async function drainInput() {
  while (input.length > 0) {
    const parsed = readFrame(input);
    if (!parsed) {
      return;
    }

    input = input.subarray(parsed.bytesRead);
    preferredFrame = parsed.frame;

    let message;
    try {
      message = JSON.parse(parsed.payload);
    } catch (err) {
      writeMessage({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: `Parse error: ${err.message}` }
      }, parsed.frame);
      continue;
    }

    activeRequests++;
    try {
      const response = await handleMessage(message);
      if (response !== null) {
        writeMessage(response, parsed.frame);
      }
    } finally {
      activeRequests--;
      maybeExit();
    }
  }
}

function maybeExit() {
  if (stdinEnded && activeRequests === 0 && input.length === 0) {
    process.exit(0);
  }
}

function readFrame(buf) {
  const textStart = buf.subarray(0, Math.min(buf.length, 32)).toString("utf8");
  if (/^Content-Length:/i.test(textStart)) {
    const headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
      return null;
    }

    const header = buf.subarray(0, headerEnd).toString("utf8");
    const match = /^Content-Length:\s*(\d+)\s*$/im.exec(header);
    if (!match) {
      throw new Error("Missing Content-Length header");
    }

    const length = Number.parseInt(match[1], 10);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buf.length < bodyEnd) {
      return null;
    }

    return {
      frame: "headers",
      payload: buf.subarray(bodyStart, bodyEnd).toString("utf8"),
      bytesRead: bodyEnd
    };
  }

  const newline = buf.indexOf("\n");
  if (newline < 0) {
    return null;
  }

  const line = buf.subarray(0, newline).toString("utf8").replace(/\r$/, "");
  return {
    frame: "newline",
    payload: line,
    bytesRead: newline + 1
  };
}

async function handleMessage(message) {
  if (Array.isArray(message)) {
    const responses = [];
    for (const item of message) {
      const response = await handleRequest(item);
      if (response !== null) {
        responses.push(response);
      }
    }
    return responses.length ? responses : null;
  }

  return handleRequest(message);
}

async function handleRequest(request) {
  if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") {
    return rpcError(request?.id ?? null, -32600, "Invalid Request");
  }

  const id = request.id;
  const isNotification = id === undefined || id === null;

  try {
    switch (request.method) {
      case "initialize":
        return rpcResult(id, {
          protocolVersion: request.params?.protocolVersion || "2025-11-25",
          capabilities: {
            tools: {},
            resources: {}
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION
          }
        });

      case "notifications/initialized":
      case "notifications/cancelled":
        return null;

      case "ping":
        return rpcResult(id, {});

      case "tools/list":
        return rpcResult(id, { tools });

      case "tools/call":
        return rpcResult(id, await callTool(request.params || {}));

      case "resources/list":
        return rpcResult(id, { resources });

      case "resources/read":
        return rpcResult(id, await readResource(request.params || {}));

      case "prompts/list":
        return rpcResult(id, { prompts: [] });

      default:
        if (isNotification) {
          return null;
        }
        return rpcError(id, -32601, `Method not found: ${request.method}`);
    }
  } catch (err) {
    if (isNotification) {
      console.error(`${SERVER_NAME}: notification failed: ${err.stack || err.message}`);
      return null;
    }
    return rpcError(id, -32000, err.message);
  }
}

async function callTool(params) {
  const name = params.name;
  const args = params.arguments || {};

  let data;
  switch (name) {
    case "get_transport_streams":
      data = enrichTransportStreams(await getJson("/api/transport-streams"));
      break;
    case "get_transport_pids":
      data = await getJson("/api/transport-pids");
      break;
    case "get_stream_models":
      data = await getJson("/api/stream-models");
      break;
    case "get_stream_model":
      data = await getOneStreamReport("/api/stream-models", args);
      break;
    case "get_stream_logs":
      data = await getJson("/api/stream-logs");
      break;
    case "get_stream_log":
      data = await getOneStreamReport("/api/stream-logs", args);
      break;
    case "get_iat_histograms":
      data = await getJson("/api/iat-histograms");
      break;
    case "get_iat_histogram":
      data = await getOneStreamReport("/api/iat-histograms", args);
      break;
    case "get_clock_reports":
      data = await getJson("/api/clock-reports");
      break;
    case "get_clock_report":
      data = await getOneStreamReport("/api/clock-reports", args);
      break;
    case "get_scte35_messages":
      data = await getJson("/api/scte35");
      break;
    case "get_scte35_messages_for_stream":
      data = await getOneStreamReport("/api/scte35", args);
      break;
    case "get_stream_summary":
      data = await getStreamSummary(args);
      break;
    case "find_streams_with_errors":
      data = await findStreamsWithErrors(args);
      break;
    case "reset_statistics":
      data = await postJson("/api/reset");
      break;
    default:
      throw new Error(`Unknown tool: ${name}`);
  }

  return jsonToolResult(data);
}

async function readResource(params) {
  const uri = params.uri;
  let data;

  switch (uri) {
    case "nic-monitor://transport-streams":
      data = enrichTransportStreams(await getJson("/api/transport-streams"));
      break;
    case "nic-monitor://transport-pids":
      data = await getJson("/api/transport-pids");
      break;
    case "nic-monitor://stream-models":
      data = await getJson("/api/stream-models");
      break;
    case "nic-monitor://stream-logs":
      data = await getJson("/api/stream-logs");
      break;
    case "nic-monitor://iat-histograms":
      data = await getJson("/api/iat-histograms");
      break;
    case "nic-monitor://clock-reports":
      data = await getJson("/api/clock-reports");
      break;
    case "nic-monitor://scte35":
      data = await getJson("/api/scte35");
      break;
    case "nic-monitor://openapi":
      data = await getJson("/openapi.json");
      break;
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }

  return {
    contents: [
      {
        uri,
        mimeType: "application/json",
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

async function getStreamSummary(args) {
  const needle = String(args.stream || "").trim();
  if (!needle) {
    throw new Error("stream is required");
  }

  const streamsDoc = enrichTransportStreams(await getJson("/api/transport-streams"));
  const stream = (streamsDoc.streams || []).find(item =>
    item.id === needle || item.source === needle || item.destination === needle
  );

  if (!stream) {
    return {
      found: false,
      query: needle,
      timestampUnix: streamsDoc.timestampUnix,
      interface: streamsDoc.interface,
      flagDefinitions: streamsDoc.flagDefinitions || {}
    };
  }

  const result = {
    found: true,
    timestampUnix: streamsDoc.timestampUnix,
    interface: streamsDoc.interface,
    flagDefinitions: streamsDoc.flagDefinitions || {},
    stream
  };

  if (args.includePids) {
    const pidsDoc = await getJson("/api/transport-pids");
    result.pids = (pidsDoc.streams || []).find(item =>
      item.id === stream.id || item.source === stream.source || item.destination === stream.destination
    )?.pids || [];
  }
  if (args.includeModel) {
    result.model = (await getOneStreamReport("/api/stream-models", { stream: needle })).stream;
  }
  if (args.includeLog) {
    result.log = (await getOneStreamReport("/api/stream-logs", { stream: needle })).stream;
  }
  if (args.includeIat) {
    result.iat = (await getOneStreamReport("/api/iat-histograms", { stream: needle })).stream;
  }
  if (args.includeClock) {
    result.clock = (await getOneStreamReport("/api/clock-reports", { stream: needle })).stream;
  }
  if (args.includeScte35) {
    result.scte35 = (await getOneStreamReport("/api/scte35", { stream: needle })).stream;
  }

  return result;
}

async function getOneStreamReport(path, args) {
  const needle = String(args.stream || "").trim();
  if (!needle) {
    throw new Error("stream is required");
  }

  const doc = await getJson(path);
  const stream = (doc.streams || []).find(item =>
    item.id === needle || item.source === needle || item.destination === needle
  );

  return {
    found: Boolean(stream),
    query: needle,
    timestampUnix: doc.timestampUnix,
    interface: doc.interface,
    stream: stream || null
  };
}

async function findStreamsWithErrors(args) {
  const minCcErrors = args.minCcErrors ?? 1;
  const includeWarnings = args.includeWarnings ?? true;
  const includeSrtRetransmissions = args.includeSrtRetransmissions ?? true;
  const hasIatThreshold = Number.isInteger(args.iatThresholdMs);

  const doc = enrichTransportStreams(await getJson("/api/transport-streams"));
  const streams = (doc.streams || []).filter(stream => {
    if ((stream.ccErrors || 0) >= minCcErrors) {
      return true;
    }
    if (hasIatThreshold && (stream.iatHighWaterMarkMs || 0) >= args.iatThresholdMs) {
      return true;
    }
    if (includeWarnings && String(stream.flags || "").trim().length > 0) {
      return true;
    }
    if (includeSrtRetransmissions && (stream.srtRetransmissions || 0) > 0) {
      return true;
    }
    return false;
  });

  return {
    timestampUnix: doc.timestampUnix,
    interface: doc.interface,
    flagDefinitions: doc.flagDefinitions || {},
    count: streams.length,
    streams
  };
}

function enrichTransportStreams(doc) {
  const flagDefinitions = doc.flagDefinitions || {};
  return {
    ...doc,
    flagDefinitions,
    streams: (doc.streams || []).map(stream => ({
      ...stream,
      warningFlags: interpretWarningFlags(stream.flags, flagDefinitions)
    }))
  };
}

function interpretWarningFlags(flags, flagDefinitions) {
  const result = [];
  const text = String(flags || "");

  for (let position = 0; position < text.length; position++) {
    const symbol = text[position];
    if (!symbol || symbol === "-") {
      continue;
    }

    const definition = flagDefinitions[symbol] || {
      position,
      symbol,
      name: "unknownFlag",
      description: "No definition was provided for this warning flag."
    };

    result.push({
      position,
      symbol,
      name: definition.name,
      description: definition.description
    });
  }

  return result;
}

async function getJson(path) {
  return requestJson("GET", path);
}

async function postJson(path) {
  return requestJson("POST", path);
}

async function requestJson(method, path) {
  const url = `${baseUrl}${path}`;
  let response;

  try {
    response = await fetch(url, { method });
  } catch (err) {
    throw new Error(`Unable to reach nic_monitor REST API at ${url}: ${err.message}`);
  }

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`nic_monitor REST API ${method} ${path} returned ${response.status}: ${body}`);
  }

  try {
    return JSON.parse(body);
  } catch (err) {
    throw new Error(`nic_monitor REST API returned non-JSON for ${method} ${path}: ${err.message}`);
  }
}

function jsonToolResult(data) {
  const text = JSON.stringify(data, null, 2);
  return {
    content: [
      {
        type: "text",
        text
      }
    ],
    structuredContent: data
  };
}

function rpcResult(id, result) {
  return {
    jsonrpc: "2.0",
    id,
    result
  };
}

function rpcError(id, code, message) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message
    }
  };
}

function writeMessage(message, frame = preferredFrame) {
  const payload = JSON.stringify(message);
  if (frame === "headers") {
    process.stdout.write(`Content-Length: ${Buffer.byteLength(payload, "utf8")}\r\n\r\n${payload}`);
  } else {
    process.stdout.write(`${payload}\n`);
  }
}

function normalizeBaseUrl(value) {
  return String(value).replace(/\/+$/, "");
}

async function smokeTest() {
  const streams = await getJson("/api/transport-streams");
  console.error(`${SERVER_NAME}: REST API reachable at ${baseUrl}`);
  console.error(`${SERVER_NAME}: streams=${Array.isArray(streams.streams) ? streams.streams.length : "unknown"}`);
}
