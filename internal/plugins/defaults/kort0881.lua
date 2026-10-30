-- kort0881.lua — kort0881/vpn-vless-configs-russia (W20 source wave).
-- RF/CIS-focused collector, Actions-driven. Layout verified against the
-- live tree 2026-10-30: the merged data/subscriptions/all.txt(+base64)
-- files are currently EMPTY upstream (zero bytes) — the real max content
-- lives in data/githubmirror/clean/<protocol>.txt (vless ~15k, trojan
-- ~2.6k, ss ~2.7k links; ~5% of lines carry upstream HTML-escaped
-- "&amp;" entities — the parse stage owns those) and output/vless.txt
-- (the largest merged file, near-strict superset of clean/vless).
-- Max-first: ingest both classes; the empty subscription files cost one
-- loud per-file skip and auto-heal if upstream repairs the merge tier.
-- The ru-sni/ and ru-sni-local/ dirs are strict FILTERED subsets —
-- deliberately not fetched (dedupe would collapse them; skipping saves
-- ~5 fetches per wave).
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; anything else loud-skips per
-- file. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "kort0881/vpn-vless-configs-russia"
local INCLUDE = {
  "data/subscriptions/",      -- all.txt + all_base64.txt (empty today)
  "data/githubmirror/clean/", -- per-protocol full sets
  "output/vless.txt",         -- merged vless output
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
    -- Upstream ships HTML-escaped query separators (&amp;): de-entity
    -- BEFORE the scheme gate or parse loses every param after the first
    -- entity (the filter's no-security dead class, ~5.2% of clean/vless).
    -- Single pass only: a double-encoded "&amp;amp;" in a real link would
    -- survive half-decoded — exotic, unobserved upstream; unhandled.
    line = line:gsub("&amp;", "&")
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
