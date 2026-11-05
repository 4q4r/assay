-- flat447.lua — FLAT447/v2ray-lists (2026-11-05 source wave).
-- Two flat merge lists: BLACK_FULL.txt and WHITE_FULL.txt — plain URI
-- lists (vless/vmess/trojan/ss/hysteria2) carrying "#announce" and
-- "#profile-*" metadata headers; upstream refreshes every ~2 hours.
-- INCLUDE is exact-filename on purpose: the repo's per-protocol splits
-- are strict subsets of the FULL merges (dedupe would collapse them), so
-- only the two merges are fetched.
--
-- Metadata header lines (leading '#') skip explicitly — the scheme gate
-- below would drop them anyway; the explicit skip documents the format
-- contract where the upstream headers are part of the list shape.
--
-- hysteria2 lines with insecure parameters are KEPT: the filter policy
-- ([filter].allow_insecure, default false) owns insecure transport and
-- drops those links loudly by design — the plugin never second-guesses
-- the pipeline.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else loud-skips per
-- file. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "FLAT447/v2ray-lists"
local INCLUDE = {
  "BLACK_FULL.txt",
  "WHITE_FULL.txt",
}

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
  local ok, decoded = pcall(publicvpn.base64.decode, flat)
  if ok and decoded:find("://", 1, true) then
    return decoded
  end
  return nil
end

local function harvest(nodes, file)
  local src = body_lines(file.content)
  if src == nil then
    publicvpn.log("skip ", file.path, ": not URI/base64 content")
    return
  end
  -- Plain-local call in the for-in header: the gopher-lua v1.1.2 VM panics
  -- on INLINE call-chain expressions there (assign-then-iterate contract).
  local kept = 0
  for line in src:gmatch("([^\r\n]+)") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line:find("^#") then
      -- Metadata headers (#announce, #profile-*) skip explicitly; the
      -- scheme gate below is the hard boundary, this branch documents the
      -- known upstream header shape. (No goto: gopher-lua is Lua 5.1.)
    elseif ingestible(line) then
      nodes[#nodes + 1] = publicvpn.node{ raw = line }
      kept = kept + 1
    end
  end
  if kept == 0 then
    publicvpn.log("skip ", file.path, ": no ingestible links")
  end
end

local function collect()
  local nodes = {}
  local files = publicvpn.github_files{ repo = REPO, include = INCLUDE }
  for _, file in ipairs(files) do
    harvest(nodes, file)
  end
  return nodes
end

return collect
