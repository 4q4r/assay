-- hidashimora.lua — Hidashimora/free-vpn-anti-rkn (W20 source wave).
-- Upstream regenerates the whole configs/ tree every minute via Actions and
-- ships two variants per source list: configs/N.1.txt = slim (max 300, every
-- 4th line) and configs/N.2.txt = the FULL list. Owner max-first rule: take
-- the max — but the upstream full-variant generation is currently broken
-- (the .2 files are essentially header-only; counts.json showed only
-- 28.2=91, 32.2=88, 33.2=4 non-zero on 2026-10-30), so the real max
-- content available is the .1 slim files plus the vpn.txt merge. Both
-- classes are ingested: the near-empty .2 files cost one loud per-file
-- skip each, any occasional non-zero .2 entries are harvested by the
-- include-dir contract, and the plugin auto-heals if upstream fixes
-- the full tier. configs/N.txt files (igareck sources) exist only in the
-- short variant and come along for free.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic) and
-- whole-body base64 subscriptions are ingestible; everything else (the
-- counts.json bookkeeping, header-only files) is loud-skipped per file —
-- not fatal. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "Hidashimora/free-vpn-anti-rkn"
local INCLUDE = { "configs/" }

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
  local nodes = {}
  local files = assay.github_files{ repo = REPO, include = INCLUDE }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end

return collect
