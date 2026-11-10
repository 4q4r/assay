-- barryfar.lua — barry-far/V2ray-Config (W20 source wave).
-- Veteran publisher, 8 main subs + per-protocol files. Verified against
-- the live tree 2026-10-30: All_Configs_Sub.txt is the union (~8.4k links,
-- plain URI list with "#profile-*" metadata headers) and
-- All_Configs_base64_Sub.txt is its whole-body-base64 twin — both are the
-- max variant; Sub1..17.txt, Base64/ and Splitted-By-Protocol/ are strict
-- subsets, deliberately not fetched (dedupe would collapse them).
--
-- CAVEAT (owner): GitHub has ToS-blocked this repo before (403, reason:
-- tos). As of 2026-10-30 the API and raw hosts answer normally, but the
-- block may return: when it does, github_files fails loud for this plugin
-- ONLY — a normal per-plugin failure; the wave continues and the breaker
-- bounds repeated losses (see [plugins].max_consecutive_failures). The
-- source may vanish; that is accepted upstream risk.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else (incl. any ssr://
-- lines) drops at the scheme gate. Go keeps owning parsing and dedupe.

local REPO = "barry-far/V2ray-Config"
local INCLUDE = {
  "All_Configs_Sub.txt",
  "All_Configs_base64_Sub.txt",
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
