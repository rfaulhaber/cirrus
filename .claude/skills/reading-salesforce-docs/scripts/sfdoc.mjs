#!/usr/bin/env node
// Finds and reads Salesforce documentation as markdown, for an agent that has to cite the
// docs rather than recall them. The docs are served three ways, and a plain fetch of any
// of them returns a JavaScript shell with no content:
//
//   developer.salesforce.com/docs/<cloud>/<product>/{guide,references}/<page>.html
//     The current developer site. Every page has a `.md` twin served as text/markdown.
//   developer.salesforce.com/docs/atlas.<locale>.[<docVersion>.]<book>.meta/<book>/<page>.htm
//     The older "atlas" books (Metadata API, Object Reference, Apex, Tooling API, …).
//     No `.md` twin; the page body comes from a JSON endpoint as HTML and is converted
//     here with pandoc. An atlas URL for a book that has moved (REST, SOAP, Bulk,
//     SOQL/SOSL, … to the current site; the Security Guide to Help) redirects there.
//   help.salesforce.com/s/articleView?id=<id>&type=<n>
//     Salesforce Help. The article body comes from the Aura action the page itself calls
//     (Help_ArticleDataController.getData), anonymously and without page state. It is an
//     internal API, so it can change without notice.
//
//   node sfdoc.mjs fetch <url> [--version <api|doc>]
//   node sfdoc.mjs find <terms…> [--limit N] [--index <name>]
//   node sfdoc.mjs toc <book|atlas url> [--depth N] [--version <api|doc>]
//
// `find` searches page titles and URLs in the llms.txt indexes Salesforce publishes,
// cached for a week under $XDG_CACHE_HOME/sfdoc. Atlas versions are given as an API
// version (60, 60.0) or a doc version (248.0); doc = 2 × API + 128.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HOST = "https://developer.salesforce.com";
const LUA_FILTER = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "atlas-clean.lua",
);
const CACHE_DIR = path.join(
  process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"),
  "sfdoc",
);
const INDEX_MAX_AGE_MS = 7 * 24 * 3600 * 1000;
// Some get_document_content requests (an unversioned or `latest` path) never answer.
const TIMEOUT_MS = 30_000;

class UsageError extends Error {}

async function get(url, init = {}) {
  try {
    return await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      ...init,
    });
  } catch (err) {
    throw new Error(
      `request failed: ${url}: ${err.cause?.message ?? err.message}`,
    );
  }
}

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const name = argv[i].slice(2);
      if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`);
      flags[name] = argv[++i];
    } else {
      positional.push(argv[i]);
    }
  }
  return { positional, flags };
}

function docVersion(value) {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0)
    throw new UsageError(`not a version: ${value}`);
  return (n >= 100 ? n : 2 * Math.trunc(n) + 128).toFixed(1);
}

// --- URL classification -------------------------------------------------------------

const ATLAS_RE =
  /^\/docs\/atlas\.([a-z]{2}-[a-z]{2})\.(?:(\d+\.\d+)\.)?([a-z0-9_]+)\.meta(?:\/([a-z0-9_]+)\/([^/?#]+?)(?:\.htm)?)?$/i;
const CURRENT_RE = /^\/docs\/[a-z0-9-]+\/.+\/(?:guide|references)\/.+$/i;

function classify(raw) {
  let text = raw.trim();
  if (/^atlas\./i.test(text)) text = `${HOST}/docs/${text}`;
  else if (text.startsWith("/docs/")) text = HOST + text;
  else if (!/^https?:\/\//i.test(text)) text = `https://${text}`;
  const url = new URL(text);
  url.hash = "";
  if (url.hostname === "help.salesforce.com") {
    const id = url.searchParams.get("id");
    if (!id) throw new UsageError(`no article id in ${raw}`);
    return {
      kind: "help",
      id,
      type: url.searchParams.get("type") ?? "5",
      release: url.searchParams.get("release") ?? undefined,
      language: url.searchParams.get("language") ?? "en_US",
    };
  }
  if (url.hostname !== "developer.salesforce.com") {
    throw new UsageError(
      `not a developer.salesforce.com or help.salesforce.com URL: ${raw}`,
    );
  }
  const atlas = url.pathname.match(ATLAS_RE);
  if (atlas) {
    const [, locale, version, book, , page] = atlas;
    return { kind: "atlas", url, locale, version, book, page };
  }
  if (CURRENT_RE.test(url.pathname)) return { kind: "current", url };
  throw new UsageError(`unrecognized docs URL shape: ${url.pathname}`);
}

// --- current site (.md twins) -------------------------------------------------------

async function fetchCurrent(url) {
  const md = new URL(url);
  md.search = "";
  md.pathname = md.pathname.replace(/\.(html?|md)$/, "") + ".md";
  const res = await get(md);
  const type = res.headers.get("content-type") ?? "";
  if (!res.ok || !type.startsWith("text/markdown")) {
    throw new Error(
      `no markdown at ${md} (HTTP ${res.status}, ${type || "no content type"})`,
    );
  }
  const html = md.href.replace(/\.md$/, ".html");
  return `<!-- source: ${html} -->\n\n${await res.text()}`;
}

// --- atlas books --------------------------------------------------------------------

async function getDocument(locale, book, version) {
  const id = `atlas.${locale}.${version ? `${version}.` : ""}${book}.meta`;
  const res = await get(`${HOST}/docs/get_document/${id}`);
  if (!res.ok) throw new Error(`atlas book ${id}: HTTP ${res.status}`);
  // An unknown book is a 200 with an empty body, not a 404.
  const body = await res.text();
  if (!body) throw new Error(`no atlas book ${id}; try: find <title words>`);
  return JSON.parse(body);
}

// A moved book's atlas URL redirects to its new home — a page on the current site, or a
// Salesforce Help article — while the book's atlas JSON stays frozen at its last release
// before the move. So an unexpected answer here is an error, not a reason to fall through
// to stale content. The check is a GET because the site's bot filter refuses HEAD.
async function movedTo(url) {
  const res = await get(url, { redirect: "manual" });
  await res.body?.cancel();
  if (res.status === 200) return undefined;
  const location = res.headers.get("location");
  const target = location && new URL(location, url);
  if (res.status >= 300 && res.status < 400 && target) {
    if (CURRENT_RE.test(target.pathname)) return { current: target };
    if (target.hostname === "help.salesforce.com") return { help: target };
  }
  throw new Error(
    `cannot tell whether ${url} has moved (HTTP ${res.status}${location ? ` → ${location}` : ""})`,
  );
}

function pandoc(html, linkRoot = HOST) {
  const args = [
    "-f",
    "html",
    "-t",
    "gfm",
    "--wrap=none",
    `--lua-filter=${LUA_FILTER}`,
  ];
  for (const [cmd, prefix] of [
    ["pandoc", []],
    ["nix", ["run", "nixpkgs#pandoc", "--"]],
  ]) {
    const run = spawnSync(cmd, [...prefix, ...args], {
      input: html,
      encoding: "utf8",
      maxBuffer: 64 << 20,
      env: { ...process.env, SFDOC_LINK_ROOT: linkRoot },
    });
    if (run.error?.code === "ENOENT") continue;
    if (run.status !== 0)
      throw new Error(`pandoc failed: ${run.stderr || run.error?.message}`);
    return run.stdout;
  }
  process.stderr.write(
    "sfdoc: pandoc unavailable (no pandoc, no nix); printing raw HTML\n",
  );
  return html;
}

async function fetchAtlas({ url, locale, version, book, page }, pinned) {
  if (!page)
    throw new UsageError(`${url} names a book, not a page; try: toc ${book}`);
  const wanted = pinned ?? (version ? docVersion(version) : undefined);
  const moved = wanted ? undefined : await movedTo(url);
  if (moved?.current) return fetchCurrent(moved.current);
  if (moved?.help) return fetchHelp(classify(moved.help.href));
  const doc = await getDocument(locale, book, wanted);
  const v = doc.version;
  const res = await get(
    `${HOST}/docs/get_document_content/${book}/${page}.htm/${locale}/${v.doc_version}`,
  );
  // An unknown page is a 200 with an empty body, not a 404.
  const body = res.ok ? await res.text() : "";
  if (!body) {
    throw new Error(
      `no page ${page}.htm in ${book} at ${v.version_text}; try: toc ${book}, or find <title words>`,
    );
  }
  const { title, content } = JSON.parse(body);
  const canonical = `${HOST}/docs/${v.version_url}/${book}/${page}.htm`;
  return `<!-- source: ${canonical} — ${doc.doc_title}, ${v.version_text}: ${title} -->\n\n${pandoc(content)}`;
}

// --- Salesforce Help ----------------------------------------------------------------

const HELP = "https://help.salesforce.com";
const HELP_TYPES = {
  5: "HelpDocs",
  1: "KBKnowledgeArticle",
  2: "KBGettingStarted",
  3: "KBQuickStarts",
};
// Knowledge articles have no single body field; the page shows these in order.
const KB_SECTIONS = [
  "description",
  "prerequisites",
  "steps",
  "task",
  "resolution",
  "additionalResources",
];

async function helpData({ id, type, release, language }) {
  const articleParameters = {
    urlName: id,
    language,
    requestedArticleType: HELP_TYPES[type],
    requestedArticleTypeNumber: type,
    ...(release ? { release } : {}),
  };
  const message = {
    actions: [
      {
        id: "1;a",
        descriptor: "aura://ApexActionController/ACTION$execute",
        callingDescriptor: "UNKNOWN",
        params: {
          namespace: "",
          classname: "Help_ArticleDataController",
          method: "getData",
          params: { articleParameters },
          cacheable: false,
          isContinuation: false,
        },
      },
    ],
  };
  const res = await get(`${HELP}/s/sfsites/aura`, {
    method: "POST",
    body: new URLSearchParams({
      message: JSON.stringify(message),
      "aura.context": JSON.stringify({
        mode: "PROD",
        app: "siteforce:communityApp",
      }),
      "aura.pageURI": "/s/",
      "aura.token": "undefined",
    }),
  });
  const text = await res.text();
  let action;
  try {
    action = JSON.parse(text).actions?.[0];
  } catch {
    action = undefined;
  }
  if (!res.ok || action?.state !== "SUCCESS") {
    throw new Error(
      `Help article endpoint refused the request (HTTP ${res.status}, ${action?.state ?? "no action in reply"}); its internal API may have changed`,
    );
  }
  return action.returnValue?.returnValue;
}

async function fetchHelp(target) {
  if (!HELP_TYPES[target.type])
    throw new UsageError(`unsupported Help article type ${target.type}`);
  let data = await helpData(target);
  // Some ids resolve only when a release is named; a NotFound reply names the current one.
  if (data?.type === "NotFound" && !target.release && data.latestRNVersion) {
    const release = data.latestRNVersion.split(".")[0];
    data = await helpData({ ...target, release });
  }
  const record = data?.record;
  const html =
    record?.Content__c ??
    KB_SECTIONS.map((k) => record?.[k])
      .filter(Boolean)
      .join("\n");
  if (!html) {
    throw new Error(
      `no Help article ${target.id} (type ${target.type}); release notes need their URL's &release=, and only recent releases are served`,
    );
  }
  const id = record.Topic_Id__c ? `${record.Topic_Id__c}.htm` : target.id;
  const major = Number(record.Version__c?.split(".")[0]);
  const isNote = id.startsWith("release-notes.");
  const canonical = `${HELP}/s/articleView?id=${id}${isNote && major ? `&release=${major}` : ""}&type=${target.type}`;
  // Help docs and knowledge articles name the same facts differently.
  const published = record.Published_Date__c ?? record.lastPublishedDate;
  const facts = [
    "Salesforce Help",
    major ? `release ${major} (API ${(major - 128) / 2}.0)` : undefined,
    published ? `published ${published.slice(0, 10)}` : undefined,
  ].filter(Boolean);
  const title = record.Title__c ?? record.title ?? target.id;
  return `<!-- source: ${canonical} — ${facts.join(", ")}: ${title} -->\n\n${pandoc(html, HELP)}`;
}

async function cmdFetch(positional, flags) {
  if (positional.length !== 1) throw new UsageError("fetch takes one URL");
  const target = classify(positional[0]);
  const pinned = docVersion(flags.version);
  if (target.kind !== "atlas" && pinned)
    process.stderr.write(
      "sfdoc: --version applies to atlas books only; fetching the current page\n",
    );
  if (target.kind === "current") return fetchCurrent(target.url);
  if (target.kind === "help") return fetchHelp(target);
  return fetchAtlas(target, pinned);
}

async function cmdToc(positional, flags) {
  if (positional.length !== 1)
    throw new UsageError("toc takes one book name or atlas URL");
  const arg = positional[0];
  const target = /^[a-z0-9_]+$/i.test(arg)
    ? { locale: "en-us", book: arg, version: undefined }
    : classify(arg);
  if (target.kind && target.kind !== "atlas")
    throw new UsageError(
      "toc reads atlas books; for the current site use find, for Help a web search",
    );
  const depth = Number(flags.depth ?? 2);
  const doc = await getDocument(
    target.locale,
    target.book,
    docVersion(flags.version) ?? docVersion(target.version),
  );
  const lines = [
    `# ${doc.doc_title} — ${doc.version.version_text} (doc ${doc.version.doc_version})`,
    `# pages: ${HOST}/docs/${doc.version.version_url}/${target.book}/<page>.htm`,
    `# other versions: ${doc.available_versions
      .filter((a) => a.doc_version !== doc.version.doc_version)
      .slice(0, 6)
      .map((a) => a.release_version)
      .join(", ")} … (--version)`,
  ];
  const walk = (nodes, level) => {
    for (const node of nodes) {
      const href = node.a_attr?.href;
      lines.push(
        `${"  ".repeat(level - 1)}${node.text}${href ? ` — ${href}` : ""}`,
      );
      if (level < depth) walk(node.children ?? [], level + 1);
    }
  };
  walk(doc.toc, 1);
  return lines.join("\n");
}

// --- llms.txt title index -----------------------------------------------------------

async function indexFiles() {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  const stamp = path.join(CACHE_DIR, ".fetched");
  const fresh =
    fs.existsSync(stamp) &&
    Date.now() - fs.statSync(stamp).mtimeMs < INDEX_MAX_AGE_MS;
  if (!fresh) {
    process.stderr.write(
      `sfdoc: refreshing the docs index into ${CACHE_DIR} (~9 MB)…\n`,
    );
    const rootRes = await get(`${HOST}/docs/llms.txt`);
    if (!rootRes.ok) throw new Error(`docs/llms.txt: HTTP ${rootRes.status}`);
    const root = await rootRes.text();
    const urls = [
      ...new Set(
        root.match(
          /https:\/\/developer\.salesforce\.com\/docs\/llms-[a-z0-9-]+\.txt/g,
        ),
      ),
    ];
    if (urls.length === 0)
      throw new Error("docs/llms.txt lists no product indexes");
    const queue = [...urls];
    const worker = async () => {
      for (let u = queue.shift(); u; u = queue.shift()) {
        const res = await get(u);
        if (!res.ok) throw new Error(`index ${u}: HTTP ${res.status}`);
        fs.writeFileSync(
          path.join(CACHE_DIR, path.basename(u)),
          await res.text(),
        );
      }
    };
    await Promise.all(Array.from({ length: 8 }, worker));
    fs.writeFileSync(stamp, new Date().toISOString());
  }
  return fs.readdirSync(CACHE_DIR).filter((f) => /^llms-.+\.txt$/.test(f));
}

async function cmdFind(positional, flags) {
  if (positional.length === 0) throw new UsageError("find needs search terms");
  const terms = positional.join(" ").toLowerCase().split(/\s+/).filter(Boolean);
  const phrase = terms.join(" ");
  const limit = Number(flags.limit ?? 25);
  const all = [];
  for (const file of await indexFiles()) {
    const index = file.replace(/^llms-|\.txt$/g, "");
    if (flags.index && !index.includes(flags.index)) continue;
    let section = "";
    for (const line of fs
      .readFileSync(path.join(CACHE_DIR, file), "utf8")
      .split("\n")) {
      if (line.startsWith("## ")) section = line.slice(3).trim();
      const m = line.match(/^- \[(.+?)\]\((\S+?)\)/);
      if (!m) continue;
      const [, title, url] = m;
      const t = title.toLowerCase();
      // Many current-site titles are bare ("Limits"); the guide is named only by the
      // section heading above them, so that and the URL slug are searched too.
      const context = `${section.toLowerCase()} ${url.toLowerCase().replace(/[-_]/g, "")}`;
      const matches = (term) =>
        t.includes(term) || context.includes(term.replace(/[-_]/g, ""));
      const matched = terms.filter(matches).length;
      if (matched === 0) continue;
      const inTitle = terms.filter((term) => t.includes(term)).length;
      const rank =
        t === phrase
          ? 0
          : t.startsWith(phrase)
            ? 1
            : inTitle === terms.length
              ? 2
              : 3;
      const where =
        url.match(/atlas\.[a-z-]+\.(?:\d+\.\d+\.)?([a-z0-9_]+)\.meta/)?.[1] ??
        section;
      all.push({
        matched,
        rank,
        inTitle,
        title,
        url,
        where: `${index}${where && where !== "Pages" ? ` / ${where}` : ""}`,
      });
    }
  }
  // Every word must match; failing that, the pages matching the most words, so one
  // word the index doesn't use ("ingest") isn't a dead end.
  const best = all.reduce((m, h) => Math.max(m, h.matched), 0);
  if (best < Math.max(1, Math.ceil(terms.length / 2)))
    return `no title or URL matches "${phrase}"; try fewer or different words, or a web search`;
  const header =
    best < terms.length
      ? [`no page matches every word; closest (${best} of ${terms.length}):`]
      : [];
  const hits = all
    .filter((h) => h.matched === best)
    .sort(
      (a, b) =>
        a.rank - b.rank ||
        b.inTitle - a.inTitle ||
        a.title.length - b.title.length,
    );
  const shown = hits
    .slice(0, limit)
    .map((h) => `${h.title} — ${h.url}  [${h.where}]`);
  if (hits.length > limit)
    shown.push(
      `… ${hits.length - limit} more (--limit, --index, or more words)`,
    );
  return [...header, ...shown].join("\n");
}

const COMMANDS = { fetch: cmdFetch, find: cmdFind, toc: cmdToc };

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const run = COMMANDS[command];
  if (!run)
    throw new UsageError(
      `usage: sfdoc.mjs {${Object.keys(COMMANDS).join("|")}} …`,
    );
  const { positional, flags } = parseArgs(rest);
  process.stdout.write(`${await run(positional, flags)}\n`);
}

main().catch((err) => {
  process.stderr.write(`sfdoc: ${err.message}\n`);
  process.exitCode = err instanceof UsageError ? 2 : 1;
});
