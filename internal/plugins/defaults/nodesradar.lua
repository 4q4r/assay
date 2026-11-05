-- nodesradar.lua — radarhub.top/v2ray.txt (2026-11-05 source wave).
-- Plain-HTTP subscription (not a GitHub repo): one whole-body-base64 list
-- of ~500 tested URIs (~122 KB today). The site's robots policy allows
-- access (verified 2026-11-05) and this plugin touches a single
-- third-party domain — the plugin circuit breaker bounds repeated
-- failures if the endpoint churns or disappears.
--
-- The fetch is pcall-guarded so transport failures raise a plugin-
-- attributed error (the breaker path) instead of an unattributed runtime
-- dump. A non-200 status fails loud the same way; an EMPTY body is an
-- upstream wipe — a valid state, not a failure — so it logs loud and
-- returns zero nodes without tripping the breaker.
--
-- max_body_bytes caps the response at 1 MiB: comfortable headroom over
-- the current ~122 KB body but far below the host default (8 MiB). If
-- this URL is ever pointed at a bulk mirror (radarhub's all_base64.txt is
-- ~10.5 MB), the oversized body fails LOUD on this cap instead of
-- silently ballooning the run.
--
-- Format contract: URI lists (vless|vmess|trojan|ss|hysteria2|hy2|tuic)
-- and whole-body base64 are ingestible; everything else loud-skips. Go
-- keeps owning URI normalization, parsing, and dedupe.

local SOURCE_URL = "https://radarhub.top/v2ray.txt"
local MAX_BODY_BYTES = 1 * 1024 * 1024

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
  -- pcall form: publicvpn.http raises on transport errors and on bodies
  -- exceeding max_body_bytes; either way the guard re-raises one loud,
  -- plugin-attributed message.
  local ok, resp = pcall(publicvpn.http, {
    url = SOURCE_URL,
    timeout = 30,
    max_body_bytes = MAX_BODY_BYTES,
  })
  if not ok then
    error("radarhub fetch failed: " .. tostring(resp))
  end
  if resp.status ~= 200 then
    error("radarhub fetch returned HTTP " .. tostring(resp.status))
  end
  if resp.body == "" then
    publicvpn.log("radarhub body is empty — zero nodes this run")
    return {}
  end
  local nodes = {}
  harvest(nodes, { path = SOURCE_URL, content = resp.body })
  return nodes
end

return collect
