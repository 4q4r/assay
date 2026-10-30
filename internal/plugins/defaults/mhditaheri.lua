-- mhditaheri.lua — MhdiTaheri/V2rayCollector (W20 source wave).
-- PHP parser over 80+ Telegram channels, Actions-driven. Verified against
-- the live tree 2026-10-30: sub/mix is the union (~2k links: ss/vless/
-- vmess/trojan) and sub/mixbase64 is its whole-body-base64 twin — both are
-- the max variant; sub/{vless,vmess,trojan,ss,tuic,hysteria}(base64) are
-- strict per-protocol subsets, deliberately not fetched (dedupe would
-- collapse them). The mix file carries a trojan://...@127.0.0.1 update
-- marker line: kept as a candidate on purpose — the parse stage owns
-- rejection (loopback), the plugin does not second-guess it.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else loud-skips per
-- file. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "MhdiTaheri/V2rayCollector"
local INCLUDE = {
  "sub/mix",
  "sub/mixbase64",
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
    if ingestible(line) then
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
