from pathlib import Path


class LuaParser:
    """Parser inicial para arquivos Lua."""

    def parse(self, file: Path) -> dict:
        text = file.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        return {
            "file": file.name,
            "lines": len(text.splitlines()),
            "characters": len(text),
        }