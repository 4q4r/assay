-- sample.lua — the tracked ingest-plugin TEMPLATE (the only plugin that
-- ships in the repository).
--
-- assay publishes as "bring your own sources": every other .lua file in the
-- plugins dir is YOURS. Drop your own plugin files into [plugins].dir and
-- they are hot-reloaded by the `assay watch` daemon — a new provider is a
-- new .lua file, no rebuild. This file materializes into the plugins dir on
-- FIRST RUN (missing dir → all embedded defaults are written 0600; an
-- existing dir is never touched — owner edits and removals persist), and it
-- demonstrates the complete host API a plugin may use.
--
-- PLUGIN CONTRACT
-- ---------------
-- * Registry id: the filename without the .lua suffix ("sample" here). The
--   id shows up in manifests, verdicts, and the status dashboard.
-- * The chunk must be SIDE-EFFECT-FREE (no network at load) and must RETURN
--   its discover function — `return collect` at the bottom. Fetching during
--   chunk execution is rejected loud ("network is not available while the
--   plugin is being loaded").
-- * The discover function takes no arguments and returns a DENSE Lua array
--   of assay.node records (no nil holes). Go owns everything downstream:
--   URI normalization, parsing, dedupe, filtering, probing.
-- * Every failure inside discover is LOUD and plugin-attributed: raise an
--   error (or let a host call raise) and the run logs the failure, feeds
--   the plugin circuit breaker, and the wave continues with the healthy
--   sources. One bad source must never kill the wave.
--
-- HOST API (the sandbox exposes exactly this — no os/io/package/debug)
-- ---------------
-- * assay.node{ raw = "vless://..." } — node constructor; validates at
--   construction time (raw must be a non-empty string) and marks the table
--   as an assay.node. Optional string hints may ride along.
-- * assay.http{ url = "...", method = "GET", body = "", headers = {...},
--   timeout = 30, max_redirects = 10, max_body_bytes = 8 MiB } — generic
--   transport; returns { status, headers, body }. Raises on transport
--   errors and on bodies exceeding max_body_bytes — both are the
--   plugin-attributed failure path (circuit breaker).
-- * assay.base64.encode(s) / assay.base64.decode(s) — std and URL-safe
--   alphabets, padding optional (the same spellings the pipeline's parser
--   accepts for share-link payloads).
-- * assay.github_files{ repo = "owner/name", include = {"a.txt"},
--   manifest = "" } — GitHub sources (contents API / manifest discovery);
--   returns an array of { path, content } rows. Raises on failure.
-- * assay.json.decode(s) / assay.json.encode(t) — JSON bridge to Lua
--   tables (decode maps JSON arrays/objects to dense tables/records).
-- * assay.log(...) — structured line into the engine log sink, prefixed
--   with the plugin id. Prefer loud skips ("skip <path>: <why>") over
--   silent drops.
--
-- THIS FILE IS A TEMPLATE: SOURCE_URL below is a placeholder
-- (https://example.invalid/...) on purpose. With the placeholder in place
-- every fetch run fails LOUD (and the circuit breaker retires the plugin
-- after a few consecutive failures) — replace SOURCE_URL with your real
-- subscription URL, or copy the file to <your-source>.lua and edit freely.
--
-- Lua dialect: gopher-lua = Lua 5.1 (no goto, no integer division).
-- Assign before iterating: the VM panics on INLINE call-chain expressions
-- in for-in headers.

local SOURCE_URL = "https://example.invalid/assay-sample-subscription.txt"

-- Ingestible share-link schemes (Lua 5.1 patterns have no alternation —
-- membership table instead). Everything else drops at the plugin boundary
-- so junk lines never inflate the pipeline's rejection counters.
local SCHEMES = {
  vless = true,
  vmess = true,
  trojan = true,
  ss = true,
  hysteria2 = true,
  hy2 = true,
  tuic = true,
}

local function ingestible(line)
  local scheme = line:match("^(%w+)://")
  return scheme ~= nil and SCHEMES[scheme] == true
end

-- body_lines returns the URI-list text for an ingestible body (plain or
-- whole-body base64) and nil for anything else — the loud-skip signal.
local function body_lines(body)
  local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed:find("://", 1, true) then
    return trimmed
  end
  -- Whitespace-flattened retry: line-wrapped base64 subscriptions must not
  -- be misclassified as junk just for interior newlines.
  local flat = trimmed:gsub("%s+", "")
  local ok, decoded = pcall(assay.base64.decode, flat)
  if ok and decoded:find("://", 1, true) then
    return decoded
  end
  return nil
end

local function harvest(nodes, path, content)
  local src = body_lines(content)
  if src == nil then
    assay.log("skip ", path, ": not URI/base64 content")
    return
  end
  local kept = 0
  -- Plain-local call in the for-in header (assign-then-iterate contract —
  -- see the dialect note in the header).
  for line in src:gmatch("([^\r\n]+)") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if ingestible(line) then
      nodes[#nodes + 1] = assay.node{ raw = line }
      kept = kept + 1
    end
  end
  if kept == 0 then
    assay.log("skip ", path, ": no ingestible links")
  end
end

local function collect()
  -- pcall form: assay.http raises on transport errors and on bodies
  -- exceeding max_body_bytes; either way the guard re-raises one loud,
  -- plugin-attributed message (the breaker path). 1 MiB keeps the defensive
  -- cap well under the host default (8 MiB) so a bulk-mirror URL can never
  -- silently balloon a run.
  local ok, resp = pcall(assay.http, {
    url = SOURCE_URL,
    timeout = 30,
    max_body_bytes = 1 * 1024 * 1024,
  })
  if not ok then
    error("sample fetch failed: " .. tostring(resp))
  end
  if resp.status ~= 200 then
    error("sample fetch returned HTTP " .. tostring(resp.status))
  end
  if resp.body == "" then
    -- An upstream wipe is a valid state, not a failure: log loud, return
    -- zero nodes, do not trip the breaker.
    assay.log("sample body is empty — zero nodes this run")
    return {}
  end
  local nodes = {}
  harvest(nodes, SOURCE_URL, resp.body)
  return nodes
end

return collect

--[=[ ALTERNATIVE SOURCE SHAPES (the rest of the host API, demonstrated)

GitHub-hosted lists via assay.github_files (include is an exact-filename
allowlist evaluated against the repo tree, so out-of-list files are never
fetched):

    local function collect_github()
      local nodes = {}
      local files = assay.github_files{
        repo = "your-name/your-lists",
        include = { "list.txt", "list_base64.txt" },
      }
      for _, file in ipairs(files) do
        harvest(nodes, file.path, file.content)
      end
      return nodes
    end

JSON catalogs via assay.json.decode (a catalog document whose entries carry
the real subscription URLs — nested fetches stay inside discover):

    local function collect_json()
      local ok, resp = pcall(assay.http, { url = SOURCE_URL, timeout = 30 })
      if not ok then
        error("sample catalog fetch failed: " .. tostring(resp))
      end
      local catalog = assay.json.decode(resp.body)
      local nodes = {}
      for _, sub in ipairs(catalog.subscriptions) do
        local rok, subresp = pcall(assay.http, { url = sub.url, timeout = 30 })
        if not rok then
          -- Per-entry isolation: one dead subscription is logged, the rest
          -- of the catalog still lands.
          assay.log("skip subscription ", sub.id, ": ", tostring(subresp))
        else
          harvest(nodes, sub.id, subresp.body)
        end
      end
      return nodes
    end

assay.base64.encode is the mirror direction (e.g. building an
auth header value or a payload for a POST body):

    assay.http{
      url = SOURCE_URL,
      method = "POST",
      headers = { Authorization = "Basic " .. assay.base64.encode(user .. ":" .. pass) },
      body = "limit=100",
    }

assay.json.encode round-trips a Lua table into a JSON body. All of the
above raise loud on failure — wrap calls whose failure should be isolated
per-entry in pcall and log the reason.
]=]
