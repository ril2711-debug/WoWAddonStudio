from pathlib import Path

from was.parser.lua_loader import LuaLoader


class AddonProject:
    """Representa um projeto de addon do World of Warcraft."""

    def __init__(self, addon_path: str):
        self.root = Path(addon_path)
        self.loader = LuaLoader(addon_path)

    def load(self):
        """Carrega todos os arquivos Lua do addon."""
        return self.loader.find_lua_files()