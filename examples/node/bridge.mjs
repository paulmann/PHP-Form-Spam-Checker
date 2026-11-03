#!/usr/bin/env node
/**
 * Node.js bridge example: call the PHP checker before processing a form.
 *
 * This is the same pattern used for the batterywizard.ru Astro site: the Node
 * server stays in charge of the form, and the PHP checker answers one question
 * — "clean / suspicious / spam" — over the CLI.
 *
 * Usage:  node examples/node/bridge.mjs register
 */

import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const php = process.env.SPAM_PHP || "php";
const script = join(root, "bin", "spam-check");
const config = process.env.SPAM_CONFIG || "";

/**
 * @param {string} formId
 * @param {Record<string, unknown>} fields
 * @param {{ip?: string, userAgent?: string, page?: string}} context
 * @returns {Promise<{status: string, score: number, reasons: string[]}>}
 */
export function checkSpam(formId, fields, context = {}) {
    const payload = JSON.stringify({ form: formId, fields, context });
    const base64 = Buffer.from(payload, "utf8").toString("base64");
    const args = [script, `--form=${formId}`, `--base64=${base64}`];
    if (config !== "") args.push(`--config=${config}`);

    return new Promise((resolve) => {
        execFile(php, args, { timeout: 5000, maxBuffer: 1048576 }, (error, stdout) => {
            if (error && !stdout) {
                resolve({ status: "error", score: 0, reasons: [error.message] });
                return;
            }
            try {
                resolve(JSON.parse(String(stdout || "{}")));
            } catch {
                resolve({ status: "error", score: 0, reasons: ["invalid checker output"] });
            }
        });
    });
}

// Demo when executed directly.
if (import.meta.url === `file://${process.argv[1]}`) {
    const formId = process.argv[2] || "contact";
    const verdict = await checkSpam(
        formId,
        {
            name: "Иван Петров",
            email: "ivan@example.ru",
            message: "Нужен отчёт по протоколу CONBAT, 48 В.",
        },
        { ip: "203.0.113.10", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0" },
    );
    console.log(JSON.stringify(verdict, null, 2));
}
