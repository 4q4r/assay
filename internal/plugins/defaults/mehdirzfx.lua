-- mehdirzfx.lua — mehdirzfx/v2ray-sub (W20 source wave).
-- Curated CATALOG, not a file source: the repo ships a single README.md
-- listing ~1153 subscription links from ~112 upstream repos under
-- "## "-headings (Mixed / VLESS / VMess / Trojan / Shadowsocks /
-- Hysteria2-TUIC = the URI+base64 categories; Clash/Mihomo YAML and
-- Sing-box JSON = out-of-scope classes; Sources-and-Credits = repo home
-- links, not subs). Verified 2026-10-30: 1118 unique ingestible URLs,
-- 946 of them on raw.githubusercontent.com.
--
-- Bounded crawl: the host API is synchronous and [plugins].run_timeout
-- defaults to 120s — fetching all ~1118 upstreams serially would get the
-- plugin abandoned loud every wave. The crawler walks the catalog in
-- SECTION ROUND-ROBIN (every category reaches the wire before the cap
-- binds) up to MAX_FETCHES fetches per run. The cap is a constant HERE —
-- plugins are owner-editable files; raise it (and/or [plugins].run_timeout,
-- explicit "0s" = unbounded) for full catalog depth. The capped crawl is
-- max-first-compatible: the catalog tail overlaps this plugin set and the
-- pipeline dedupes at parse, while the long tail of catalog-only repos
-- still lands.
--
-- Loud-skip classes: clash/mihomo sections, sing-box/JSON sections and
-- credits sections log one per-section line; YAML/JSON/sing-box URLs and
-- non-ingestible bodies log per URL (the format gate stays the final
-- arbiter — an extension-less URL serving YAML skips at harvest).

local CATALOG_URL =
  "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/README.md"

-- Fetch budget per run, SAFE BY CONSTRUCTION under the default 120s
-- [plugins].run_timeout: a run timeout abandonment loses the whole result,
-- so the worst case must fit — 25 fetches × 3s timeout = 75s nested + the
-- 30s catalog fetch = 105s worst case vs the 120s run_timeout (a 15s
-- margin), typically <15s. Nested fetches cap at 2 MiB: the host REJECTS
-- oversized bodies entirely (loud, no partial) — the budget stays
-- protected and the oversized sub is lost for that wave. The cap
-- is a constant HERE — plugins are owner-editable files; raise it (and/or
-- [plugins].run_timeout, explicit "0s" = unbounded) for full catalog depth.
-- The capped crawl is max-first-compatible: the catalog tail overlaps this
-- plugin set and the pipeline dedupes at parse, while the long tail of
-- catalog-only repos still lands.

local MAX_FETCHES = 25

-- Out-of-scope catalog sections (substring-matched lowercase).
local SKIP_SECTION = {
  clash = true,
  mihomo = true,
  sing = true,
  credit = true,
}

local function section_skipped(name)
  local low = name:lower()
  for word in pairs(SKIP_SECTION) do
    if low:find(word, 1, true) then
      return true
    end
  end
  return false
end

-- URL-level skip: YAML/JSON profile files and sing-box endpoints. Plain
-- find (no patterns) — the dots are literal. The body gate below stays
-- the final arbiter: an extension-less URL serving YAML skips at harvest.
local function url_skipped(url)
  local low = url:lower()
  if low:find(".yaml", 1, true) or low:find(".yml", 1, true)
    or low:find(".json", 1, true) or low:find("sing-box", 1, true)
    or low:find("singbox", 1, true) then
    return true
  end
  return false
end

-- github.com blob pages carry HTML, not the file: rewrite to the raw host
-- (and strip any "#" suffix) so both catalog spellings dedupe to one fetch.
local function normalize(url)
  local out = url:gsub("#.*$", "")
  out = out:gsub("^https?://github%.com/([^/]+)/([^/]+)/blob/(.+)$",
    "https://raw.githubusercontent.com/%1/%2/%3")
  return out
end

-- Extract per-section ingestible URL lists in catalog order, logging the
-- out-of-scope classes loud (one line per skipped section, one per
-- skipped URL inside kept sections).
local function catalog_lists(md)
  local lists = {}
  local current = nil
  local name = ""
  local skipped = 0
  for line in md:gmatch("([^\r\n]+)") do
    local heading = line:match("^##%s+(.-)%s*$")
    if heading then
      if current == nil and skipped > 0 then
        assay.log("skip section '", name, "': ", skipped,
          " out-of-scope links (clash/singbox/credits or yaml/json)")
      end
      current = nil
      name = heading
      skipped = 0
      if not section_skipped(heading) then
        current = {}
        lists[#lists + 1] = current
      end
    else
      -- Bare URL match: the catalog mixes bare links (fenced blocks) and
      -- markdown [name](url) links — matching any http(s) substring covers
      -- both (a trailing markdown ")" is trimmed below).
      local url = line:match("(https?://%S+)")
      if url then
        url = url:gsub("[%)%]%,>%.]+$", "")
        if url_skipped(url) then
          assay.log("skip out-of-scope url ", url)
          skipped = skipped + 1
        elseif current == nil then
          skipped = skipped + 1
        else
          current[#current + 1] = url
        end
      end
    end
  end
  if current == nil and skipped > 0 then
    assay.log("skip section '", name, "': ", skipped,
      " out-of-scope links (clash/singbox/credits or yaml/json)")
  end
  return lists
end

-- Round-robin across sections: item 1 of every list first, then item 2,
-- ... — the fetch cap cannot starve the tail categories.
local function round_robin(lists)
  local queue = {}
  local cursors = {}
  local more = true
  while more do
    more = false
    for _, urls in ipairs(lists) do
      local next_url = urls[(cursors[urls] or 0) + 1]
      if next_url then
        cursors[urls] = (cursors[urls] or 0) + 1
        queue[#queue + 1] = next_url
        more = true
      end
    end
  end
  return queue
end

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

local function harvest(nodes, file)
  local src = body_lines(file.content)
  if src == nil then
    assay.log("skip ", file.path, ": not URI/base64 content")
    return
  end
  -- Plain-local call in the for-in header: the gopher-lua v1.1.2 VM panics
  -- on INLINE call-chain expressions there (assign-then-iterate contract).
  local kept = 0
  for line in src:gmatch("([^\r\n]+)") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if ingestible(line) then
      nodes[#nodes + 1] = assay.node{ raw = line }
      kept = kept + 1
    end
  end
  if kept == 0 then
    assay.log("skip ", file.path, ": no ingestible links")
  end
end

local function collect()
  local resp = assay.http{ url = CATALOG_URL, timeout = 30 }
  if resp.status ~= 200 then
    error("catalog fetch returned HTTP " .. tostring(resp.status))
  end
  local queue = round_robin(catalog_lists(resp.body))
  local seen = {}
  local nodes = {}
  local used = 0
  for _, raw_url in ipairs(queue) do
    if used >= MAX_FETCHES then
      assay.log("catalog crawl capped at ", MAX_FETCHES,
        " fetches per run — raising MAX_FETCHES in this file goes deeper")
      break
    end
    local url = normalize(raw_url)
    if not seen[url] then
      seen[url] = true
      used = used + 1
      local ok, sub = pcall(assay.http,
    { url = url, timeout = 3, max_body_bytes = 2 * 1024 * 1024 })
      if not ok then
        assay.log("fetch failed ", url, ": ", tostring(sub))
      elseif sub.status ~= 200 then
        assay.log("skip ", url, ": HTTP ", tostring(sub.status))
      else
        harvest(nodes, { path = url, content = sub.body })
      end
    end
  end
  return nodes
end

return collect
