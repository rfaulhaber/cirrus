---
name: reading-salesforce-docs
description: Use when a task needs facts from official Salesforce documentation — Metadata API types, sObject fields, REST/SOAP/Bulk/Tooling API behavior, limits, Apex, OAuth and connected apps, permissions and sharing — or when WebFetch or curl on developer.salesforce.com or help.salesforce.com returns HTTP 403, an empty JavaScript shell, or nothing usable.
---

# Reading Salesforce docs

## Overview

WebFetch gets **HTTP 403** on every developer.salesforce.com URL (`.html`, `.htm`, `.md`
alike), a browser `User-Agent` gets the same 403, and a plain fetch of a developer page or a
Help article returns a JavaScript shell with no content. The sites serve the text through
other channels — a `.md` twin of every current developer page, a JSON endpoint for the older
"atlas" books, the data call Help's own article page makes, llms.txt title indexes — and
`scripts/sfdoc.mjs` reads them. Use it, and quote what it prints, never a search snippet or
memory.

## Quick reference

From the repo root (Node is in the dev shell; `pandoc` comes from `PATH` or `nix run`):

```
node .claude/skills/reading-salesforce-docs/scripts/sfdoc.mjs find <title words> [--index product-docs|platform|…] [--limit N]
node .claude/skills/reading-salesforce-docs/scripts/sfdoc.mjs fetch <url> [--version 60]
node .claude/skills/reading-salesforce-docs/scripts/sfdoc.mjs toc <book> [--depth 3] [--version 60]
```

`fetch` takes any developer.salesforce.com docs URL or help.salesforce.com article URL
(`#anchor` and all), follows moved pages, and prints markdown headed
`<!-- source: <canonical URL> — <guide>, <release>: <title> -->`. Cite that URL and release.
Large pages (Profile is ~48 KB): redirect to a scratch file and grep or Read the section.

## Finding the page

Go down the list until something hits:

1. **A URL** from code, a doc link, or a link inside a fetched page: `fetch` it.
2. **Title search**: `find PermissionSetGroup`, `find bulk api 2.0 limits` — ~58,000
   developer-doc titles, guide names and URL slugs (not Help). Use few words and write type
   names as one word; with no full match it shows the closest pages.
3. **Known book, unknown page**: `toc api_meta --depth 3 | grep -i sharing`.
4. **A concept, or anything on Help**: WebSearch `site:help.salesforce.com <terms>` (or
   `site:developer.salesforce.com`), then `fetch` the result URL. Snippets are leads only.

## Where Fabrum's topics live

| Topic                                                                                                                                                       | Where                                            |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| Profile, PermissionSet, PermissionSetGroup, MutingPermissionSet metadata                                                                                    | book `api_meta`                                  |
| PermissionSet, ObjectPermissions, FieldPermissions, SetupEntityAccess, PermissionSetAssignment, PermissionSetGroupComponent, UserLicense, `*Share` sObjects | book `object_reference`                          |
| Tooling API objects; Apex                                                                                                                                   | books `api_tooling`; `apexcode`, `apexref`       |
| Metadata types' source-tracking and packaging support                                                                                                       | `find metadata coverage report`                  |
| REST (incl. composite), SOAP, Bulk API 2.0, SOQL/SOSL, limits                                                                                               | current developer site — `find`                  |
| What a permission grants, sharing, OWD, licenses                                                                                                            | Help (titles: `toc securityImplGuide --depth 3`) |
| OAuth flows, connected and external client apps, refresh tokens                                                                                             | Help                                             |

## Versions

Pages default to the current release, named in the source line (doc version = 2 × API +
128; Help's `release 264` is API 68.0). When behavior depends on the API version the code
calls, pin an atlas page: `--version 60` (API) or `--version 248.0` (doc). The current
developer site and Help serve only the latest release; Help release notes, only the last few
(keep the URL's `&release=`). An atlas book older than what `toc api_meta` reports is frozen
— its topics moved; find their current home instead of citing it.

Help is read through an internal data call, not a published API. If `fetch` says the Help
endpoint refused the request, report the fact as unverified.

## Common mistakes

| Mistake                                                                          | Instead                                                                                    |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| Retrying WebFetch or URL variants after a 403                                    | The 403 refuses WebFetch's client on every URL form. Use `sfdoc.mjs`.                      |
| A browser or crawler `User-Agent` to get past a 403 or JS shell                  | Never: the browser UA is what gets refused, and impersonating a crawler is not acceptable. |
| Answering from search summaries, blogs, Trailhead or memory after a failed fetch | Fetch and quote the official page, or say the fact is unverified.                          |
| Calling the atlas JSON or Help endpoint by hand                                  | `fetch` handles moved books, frozen copies, release retries, empty "not found" replies.    |
| Taking "no page" as proof a feature doesn't exist                                | Page ids aren't titles: `find`, `toc`, then the web.                                       |
