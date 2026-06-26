#!/usr/bin/env node
import childProcess from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import puppeteer from "puppeteer-core";

function log(level, message, details = {}) {
  process.stdout.write(`${JSON.stringify({
    timestamp: new Date().toISOString(),
    logLevel: level,
    context: "worker",
    message,
    details
  })}\n`);
}

function browserExecutable() {
  for (const candidate of [process.env.BROWSER_BIN, "/usr/bin/google-chrome", "/usr/bin/chromium-browser"]) {
    if (!candidate) continue;
    try {
      childProcess.execFileSync("test", ["-x", candidate]);
      return candidate;
    } catch {
      // continue
    }
  }
  throw new Error("Chromium executable not found");
}

async function main() {
  const [, , cookiesPath, outputPath] = process.argv;
  if (!cookiesPath || !outputPath) {
    throw new Error("usage: cookie-profile.mjs <cookies.json> <profile.tar.gz>");
  }

  const cookies = JSON.parse(await fs.readFile(cookiesPath, "utf8"));
  if (!Array.isArray(cookies) || cookies.length === 0) {
    throw new Error("cookie profile contains no cookies");
  }

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "warcdriver-cookie-profile-"));
  const userDataDir = path.join(root, "profile");
  await fs.mkdir(userDataDir, { recursive: true });

  log("info", "Creating Browsertrix cookie profile", { cookies: cookies.length });
  const browser = await puppeteer.launch({
    executablePath: browserExecutable(),
    userDataDir,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-background-networking",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-sync",
      "--remote-allow-origins=*"
    ]
  });

  try {
    await browser.setCookie(...cookies);
    log("info", "Stored cookies in temporary browser profile", { cookies: cookies.length });
  } finally {
    await browser.close();
  }

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  childProcess.execFileSync("tar", ["czf", outputPath, "-C", userDataDir, "."]);
  await fs.rm(root, { recursive: true, force: true });
  log("info", "Browsertrix cookie profile ready", { profile: outputPath });
}

main().catch((err) => {
  log("error", "Browsertrix cookie profile generation failed", { error: err?.message || String(err) });
  process.exit(1);
});
