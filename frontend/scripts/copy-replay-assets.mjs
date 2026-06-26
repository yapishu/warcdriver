import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const replayPackage = join(root, "node_modules", "replaywebpage");
const outDir = join(root, "public", "replay");

await mkdir(outDir, { recursive: true });
await copyFile(join(replayPackage, "ui.js"), join(outDir, "ui.js"));
await copyFile(join(replayPackage, "sw.js"), join(outDir, "sw.js"));
