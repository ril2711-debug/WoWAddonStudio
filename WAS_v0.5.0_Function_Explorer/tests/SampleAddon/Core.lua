local function Init()
    local frame = CreateFrame("Frame")
    frame:RegisterEvent("PLAYER_LOGIN")
    BuildUI()
end

function BuildUI()
    C_Timer.After(1, Refresh)
end

local function Refresh()
    Settings.OpenToCategory("Demo")
end
