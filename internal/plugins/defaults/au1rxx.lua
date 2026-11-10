-- au1rxx.lua — Au1rxx/free-vpn-subscriptions (W20 source wave).
-- 26-country split publisher ("2000 fastest", Actions-driven). Verified
-- against the live tree 2026-10-30: output/all-verified/ holds three file
-- classes — clash-NNNN.yaml and singbox-NNNN.json (OUT of pipeline scope:
-- YAML/JSON profiles) and v2ray-base64-NNNN.txt (the V2Ray base64 TXT
-- variant, ~2000 links per shard, 8181 unique across 6 shards). The
-- by-country v2ray-base64-CC.txt files are a strict SUBSET of the
-- all-verified shards (sampled DE/NL/US 2026-10-30: 0 lines outside the
-- union) — deliberately not fetched; dedupe would collapse them and
-- skipping saves ~40 fetches per wave.
--
-- The clash/singbox classes ship inside the included directory: they are
-- loud-skipped per file below (the owner-mandated skip class), not fatal.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else loud-skips per
-- file. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "Au1rxx/free-vpn-subscriptions"
local INCLUDE = { "output/all-verified/" }

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
