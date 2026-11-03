#!/usr/bin/env node
/**
 * Node.js bridges for PHP Form Spam Checker 2.0.
 *
 * The Node server stays in charge of the request; PHP answers two questions:
 *
 *   - checkSpam()      -> form verdict    (bin/spam-check)
 *   - inspectRequest() -> WAF verdict     (bin/waf-check, 2.0)
 *
 * This is the pattern used for the batterywizard.ru Astro site: the WAF runs
 * before the API handler, the form check runs before the lead is stored.
 *
 * Usage:  node examples/node/bridge.mjs register
 *
 * Environment:
 *   SPAM_PHP     PHP binary           (default: "php", e.g. /usr/bin/php8.5)
 *   SPAM_CONFIG  configuration file   (optional; site config works too)
 */

import { execFile } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const php = process.env.SPAM_PHP || "php";
const spamCheck = join(root, "bin", "spam-check");
const wafCheck = join(root, "bin", "waf-check");
const config = process.env.SPAM_CONFIG || "";

/**
 * Run one bridge and parse its JSON verdict.
 *
 * @param {string} script
 * @param {string[]} args
 * @returns {Promise<Record<string, unknown>>}
 */
function runBridge(script, args) {
    return new Promise((resolve) => {
        execFile(php, [script, ...args], { timeout: 5000, maxBuffer: 1048576 }, (error, stdout) => {
            // A non-zero exit may still carry a valid verdict (exit 1/2 for
            // "suspicious"/"spam", exit 2 for a WAF block).
            if (error && !stdout) {
                resolve({ status: "error", blocked: false, score: 0, reasons: [error.message] });
                return;
            }

            try {
                resolve(JSON.parse(String(stdout || "{}")));
            } catch {
                resolve({
                    status: "error",
                    blocked: false,
                    score: 0,
                    reasons: ["invalid checker output"],
                });
            }
        });
    });
}

/**
 * Form verdict.
 *
 * Output shape is unchanged from 1.x: form, status (clean|suspicious|spam),
 * score, reasons, checks. Per-check status values are now
 * spam|ham|uncertain|error.
 *
 * @param {string} formId
 * @param {Record<string, unknown>} fields
 * @param {{ip?: string, userAgent?: string, page?: string, referer?: string}} context
 * @returns {Promise<Record<string, unknown>>}
 */
export function checkSpam(formId, fields, context = {}) {
    const payload = JSON.stringify({ form: formId, fields, context });
    const base64 = Buffer.from(payload, "utf8").toString("base64");
    const args = [`--form=${formId}`, `--base64=${base64}`];
    if (config !== "") args.push(`--config=${config}`);

    return runBridge(spamCheck, args);
}

/**
 * WAF verdict for one HTTP request (2.0).
 *
 * IMPORTANT: pass `host` and `content-type` headers. The WAF `protocol` rule
 * scores their absence (softly), and together with the default block threshold
 * that can block an otherwise clean request.
 *
 * Output: {blocked, status: clean|suspicious|blocked|disabled, score, findings, reasons}
 * Fail open on status "error": let the request through and log it.
 *
 * @param {{
 *   method?: string, uri?: string, ip?: string,
 *   headers?: Record<string, string>,
 *   cookies?: Record<string, string>,
 *   query?: Record<string, unknown>,
 *   body?: string,
 *   fields?: Record<string, unknown>,
 *   form?: string
 * }} request
 * @returns {Promise<Record<string, unknown>>}
 */
export function inspectRequest(request) {
    const payload = JSON.stringify({
        method: request.method || "GET",
        uri: request.uri || "/",
        ip: request.ip || "",
        headers: request.headers || {},
        cookies: request.cookies || {},
        query: request.query || {},
        body: request.body || "",
        fields: request.fields || {},
        form: request.form || "default",
    });
    const base64 = Buffer.from(payload, "utf8").toString("base64");
    const args = [`--base64=${base64}`];
    if (config !== "") args.push(`--config=${config}`);

    return runBridge(wafCheck, args);
}

/**
 * Typical Astro/Express usage:
 *
 *   app.use(async (req, res, next) => {
 *     const waf = await inspectRequest({
 *       method: req.method,
 *       uri: req.originalUrl,
 *       ip: req.ip,
 *       headers: req.headers,        // includes host + content-type
 *       body: req.rawBody || "",
 *       query: req.query,
 *       fields: req.body,
 *       form: "lead",
 *     });
 *
 *     if (waf.status === "error") return next();        // fail open
 *     if (waf.status === "disabled") return next();     // WAF off in config
 *     if (waf.blocked) return res.status(403).json({ ok: false });
 *
 *     next();
 *   });
 */

// Demo when executed directly (pathToFileURL keeps this working on Windows).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    const formId = process.argv[2] || "contact";

    const verdict = await checkSpam(
        formId,
        {
            name: "Иван Петров",
            email: "ivan@example.ru",
            message: "Нужен отчёт по протоколу CONBAT, 48 В.",
        },
        {
            ip: "203.0.113.10",
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0",
            page: "/contacts/",
        },
    );

    const waf = await inspectRequest({
        method: "POST",
        uri: "/contacts/",
        ip: "203.0.113.10",
        headers: {
            host: "example.ru",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0",
        },
        body: "message=%D0%9D%D1%83%D0%B6%D0%B5%D0%BD+%D0%BE%D1%82%D1%87%D1%91%D1%82",
        fields: { message: "Нужен отчёт по протоколу CONBAT, 48 В." },
        form: formId,
    });

    console.log(JSON.stringify({ form: verdict, waf }, null, 2));
}
