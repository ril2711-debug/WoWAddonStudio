local function ScanGlobals()
    for key, value in pairs(_G) do
        print(key)
    end
end
