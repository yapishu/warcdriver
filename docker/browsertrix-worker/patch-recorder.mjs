#!/usr/bin/env node

import fs from "node:fs/promises";

const recorderPath = process.argv[2];
if (!recorderPath) {
  throw new Error("usage: patch-recorder.mjs <browsertrix-recorder.js>");
}

let source = await fs.readFile(recorderPath, "utf8");

const responseNeedle = "const httpHeaders = reqresp.getResponseHeadersDict(reqresp.payload.length);";
const requestNeedle = "const httpHeaders = reqresp.getRequestHeadersDict();";
if (!source.includes(responseNeedle) || !source.includes(requestNeedle)) {
  throw new Error("Browsertrix recorder layout changed; refusing to build without verified header redaction");
}

const helper = `const WARCDRIVER_SENSITIVE_REQUEST_HEADERS = new Set([
    "authorization",
    "cookie",
    "proxy-authorization",
]);
const WARCDRIVER_SENSITIVE_RESPONSE_HEADERS = new Set(["set-cookie"]);
function warcdriverStripSensitiveHeaders(headers, blocked) {
    for (const name of Object.keys(headers)) {
        if (blocked.has(name.toLowerCase())) {
            delete headers[name];
        }
    }
    return headers;
}
`;

source = source.replace(
  "// response\nfunction createResponse",
  `// response\n${helper}function createResponse`,
);
source = source.replace(
  responseNeedle,
  "const httpHeaders = warcdriverStripSensitiveHeaders(reqresp.getResponseHeadersDict(reqresp.payload.length), WARCDRIVER_SENSITIVE_RESPONSE_HEADERS);",
);
source = source.replace(
  requestNeedle,
  "const httpHeaders = warcdriverStripSensitiveHeaders(reqresp.getRequestHeadersDict(), WARCDRIVER_SENSITIVE_REQUEST_HEADERS);",
);

await fs.writeFile(recorderPath, source);
