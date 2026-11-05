-- igareck.lua — igareck/vpn-configs-for-russia (2026-11-05 source wave).
-- RF-focused publisher shipping curated protocol splits. INCLUDE is
-- exact-filename for the five research-verified files: the two BLACK
-- vless lists (desktop + mobile), the two BLACK ss lists (all + weak-DPI),
-- and the white REALITY mobile list. Other files in the repo
-- (README bookkeeping, duplicated per-protocol variants) are strict
-- subsets or out of scope and are deliberately not fetched.
--
-- NOTE on "BLACK_SS+All_RUS.txt" — the filename carries a literal '+':
-- the github_files helper builds raw URLs by plain string concatenation
-- (internal/fetch rawURL — no URL escaping), so the include entry is used
-- verbatim as the URL path. Include matching compares the literal
-- repo-relative path from the git-trees API, so a "%2B" spelling would
-- never match and discovery would fail loud. Go's net/url keeps '+'
-- literal in request paths (legal RFC 3986 path segment) and the raw host
-- serves the file — the wire form is pinned by the fixture test
-- (TestIgareckFixture asserts the request arrives unescaped).
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else loud-skips per
-- file. Go keeps owning URI normalization, parsing, and dedupe.

local REPO = "igareck/vpn-configs-for-russia"
local INCLUDE = {
  "BLACK_VLESS_RUS.txt",
  "BLACK_VLESS_RUS_mobile.txt",
  "BLACK_SS+All_RUS.txt",
  "BLACK_SS_WEAK_DPI_RUS.txt",
  "Vless-Reality-White-Lists-Rus-Mobile.txt",
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
