-- epodonios.lua — Epodonios/v2ray-configs (W10 Lua-plugin migration).
-- Behavior parity with the former Go github-contents source: same repo,
-- same per-protocol split files, D9 discovery via publicvpn.github_files.

local REPO = "Epodonios/v2ray-configs"
local INCLUDE = {
  "Splitted-By-Protocol/vless.txt",
  "Splitted-By-Protocol/trojan.txt",
}

local function body_lines(body)
  local trimmed = body:gsub("^%s+", ""):gsub("%s+$", "")
  if trimmed:find("://", 1, true) then
    return body
  end
  local ok, decoded = pcall(publicvpn.base64.decode, trimmed)
  if ok and decoded:find("://", 1, true) then
    return decoded
  end
  return body
end

local function collect()
  local nodes = {}
  local files = publicvpn.github_files{ repo = REPO, include = INCLUDE }
  for _, file in ipairs(files) do
    -- NOTE: the loop text is assigned BEFORE gmatch on purpose: gopher-lua
    -- v1.1.2 panics (nil deref) when a for-in iterator is fed an INLINE
    -- call-chain expression — assign-then-iterate is the documented
    -- workaround (pinned by the plugin fixture tests).
    local text = body_lines(file.content) .. "\n"
    for line in text:gmatch("([^\r\n]*)\n") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and not line:find("^#") and not line:find("^//") then
        nodes[#nodes + 1] = publicvpn.node{ raw = line }
      end
    end
  end
  return nodes
end

return collect
