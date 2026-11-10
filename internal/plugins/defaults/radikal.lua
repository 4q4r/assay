-- radikal.lua — 0xRadikal/Free-v2ray-Configs (W10 Lua-plugin migration).
-- Behavior parity with the former Go manifest source: reads index.json and
-- follows the .txt file URLs it lists (SECURE list = forward-secrecy
-- pre-filter). The manifest discovery logic lives in the github_files
-- helper (manifest = "index.json") — the plugin stays thin.

local REPO = "0xRadikal/Free-v2ray-Configs"
local MANIFEST = "index.json"
local INCLUDE = { "secure/configs.txt" }

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
  local files = assay.github_files{
    repo = REPO,
    manifest = MANIFEST,
    include = INCLUDE,
  }
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
