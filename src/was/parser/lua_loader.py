from pathlib import Path


class LuaLoader:
    """Responsável por localizar e carregar arquivos Lua."""

    def __init__(self, addon_path: str):
        self.addon_path = Path(addon_path)

    def find_lua_files(self) -> list[Path]:
        """Localiza todos os arquivos .lua do addon."""
        return sorted(self.addon_path.rglob("*.lua"))

    def read(self, file: Path) -> str:
        """Lê o conteúdo de um arquivo Lua."""
        return file.read_text(
            encoding="utf-8",
            errors="ignore",
        )