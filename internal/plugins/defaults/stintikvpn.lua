-- stintikvpn.lua — Stintik-123/StintikVPN (W10 REFERENCE PLUGIN).
-- This is the demo of the network API's full flexibility: fetch data.json,
-- iterate the subscription list, nested-fetch every upstream subscription,
-- and return the collected nodes. data.json shape (verified 2026-10-28):
--   { "updated": "...",
--     "subscriptions": [ { "id": "...", "url": "https://...", ... } ],
--     "proxies": [ ... MTProto links — NOT proxy-subscription material ] }
--
-- One dead upstream subscription must not kill the plugin: each nested
-- fetch is pcall-guarded and logged loud (the pipeline's per-plugin
-- continuation handles the rest).
--
-- NOTE: the "black-main" subscription points at the mahdibland full merge,
-- whose own README warns it crashes some clients. The pipeline's filter
-- (reality/tls + insecure policy), out-of-band probe, -test gate, and
-- select caps are the safety layer here — nodes only ever reach the live
-- client through select → render → activate.

local DATA_URL =
  "https://raw.githubusercontent.com/Stintik-123/StintikVPN/main/docs/data.json"

local function body_lines(body)
  local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed:find("://", 1, true) then
    return body
  end
  local ok, decoded = pcall(assay.base64.decode, trimmed)
  if ok and decoded:find("://", 1, true) then
    return decoded
  end
  return body
end

local function add_links(nodes, body, sub_id)
  -- NOTE: assign-then-iterate — gopher-lua v1.1.2 panics on inline
  -- call-chain for-in expressions (see the repo README plugin guide).
  local text = body_lines(body) .. "\n"
  for line in text:gmatch("([^\r\n]*)\n") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and not line:find("^#") and not line:find("^//") then
      nodes[#nodes + 1] = assay.node{ raw = line, remark = sub_id }
    end
  end
end

local function collect()
  local nodes = {}
  local resp = assay.http{ url = DATA_URL, timeout = 30 }
  if resp.status ~= 200 then
    error("data.json fetch returned HTTP " .. tostring(resp.status))
  end
  local ok, data = pcall(assay.json.decode, resp.body)
  if not ok then
    error("data.json is not valid JSON: " .. tostring(data))
  end
  for _, sub in ipairs(data.subscriptions or {}) do
    local fetched, subresp = pcall(assay.http, { url = sub.url, timeout = 30 })
    if not fetched then
      assay.log("subscription ", sub.id, " failed: ", subresp)
    elseif subresp.status ~= 200 then
      assay.log("subscription ", sub.id, " returned HTTP ", subresp.status)
    else
      add_links(nodes, subresp.body, sub.id)
    end
  end
  return nodes
end

return collect
