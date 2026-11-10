-- matin.lua — MatinGhanbari/v2ray-configs (W10 Lua-plugin migration).
-- Behavior parity with the former Go github-contents source: same repo, same
-- include patterns, D9 discovery via the assay.github_files helper.
-- Contract: the chunk is side-effect-free and returns the discover function;
-- all fetching happens inside it.
--
-- Bodies are handed to the pipeline as one raw link per line; base64
-- subscription payloads are decoded via assay.base64.decode using the
-- same strict rule as the Go parser (no "://" anywhere, decodes cleanly,
-- decoded text contains a scheme). Non-link lines are re-validated and
-- rejected by the Go parse stage exactly as before.

local REPO = "MatinGhanbari/v2ray-configs"
local INCLUDE = {
  "subscriptions/v2ray/super-sub.txt",
  "subscriptions/v2ray/all_sub.txt",
  "subscriptions/filtered/subs/vless.txt",
}

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

local function collect()
  local nodes = {}
  local files = assay.github_files{ repo = REPO, include = INCLUDE }
  for _, file in ipairs(files) do
    -- NOTE: the loop text is assigned BEFORE gmatch on purpose: gopher-lua
    -- v1.1.2 panics (nil deref) when a for-in iterator is fed an INLINE
    -- call-chain expression — assign-then-iterate is the documented
    -- workaround (pinned by the plugin fixture tests).
    local text = body_lines(file.content) .. "\n"
    for line in text:gmatch("([^\r\n]*)\n") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and not line:find("^#") and not line:find("^//") then
        nodes[#nodes + 1] = assay.node{ raw = line }
      end
    end
  end
  return nodes
end

return collect
