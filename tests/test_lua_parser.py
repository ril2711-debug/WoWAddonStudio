from pathlib import Path

from was.parser.lua_parser import LuaParser


def test_lua_parser():
    parser = LuaParser()

    result = parser.parse(
        Path("tests/SampleAddon/Core.lua")
    )

    assert result["file"] == "Core.lua"
    assert result["lines"] > 0