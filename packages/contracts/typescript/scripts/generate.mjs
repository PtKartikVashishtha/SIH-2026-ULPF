/**
 * Generate TypeScript interfaces from JSON Schema source of truth.
 *
 * Usage: node scripts/generate.mjs
 *
 * Reads all *.schema.json from packages/contracts/schemas/ and writes
 * TypeScript interfaces to src/generated.ts.
 */

import { compileFromFile } from "json-schema-to-typescript";
import { readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const SCHEMA_DIR = resolve(__dirname, "../../schemas");
const OUT_FILE = resolve(__dirname, "../src/generated.ts");

async function main() {
  const files = (await readdir(SCHEMA_DIR)).filter((f) =>
    f.endsWith(".schema.json"),
  );
  files.sort();

  /** @type {string[]} */
  const chunks = [
    "// AUTO-GENERATED from packages/contracts/schemas/*.schema.json",
    "// Do NOT edit by hand — run: npm run generate",
    "",
  ];

  for (const file of files) {
    const fullPath = join(SCHEMA_DIR, file);
    const ts = await compileFromFile(fullPath, {
      bannerComment: "",
      additionalProperties: false,
      style: {
        semi: true,
        singleQuote: false,
        trailingComma: "all",
      },
    });
    chunks.push(`// --- ${file} ---`);
    chunks.push(ts);
    chunks.push("");
  }

  await writeFile(OUT_FILE, chunks.join("\n"), "utf-8");
  console.log(`Generated ${OUT_FILE} from ${files.length} schemas.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
