from pathlib import Path

from was.models.addon_manifest import AddonManifest


class TOCLoader:
    """Lê e interpreta o arquivo .toc de um addon."""

    def __init__(self, addon_path: str):
        self.root = Path(addon_path)

    def find_toc(self) -> Path | None:
        toc_files = sorted(self.root.glob("*.toc"))
        return toc_files[0] if toc_files else None

    def load(self) -> AddonManifest:
        toc = self.find_toc()

        if toc is None:
            raise FileNotFoundError(
                f"Nenhum arquivo .toc encontrado em: {self.root}"
            )

        manifest = AddonManifest()

        lines = toc.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()

        for raw_line in lines:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("##"):
                self._parse_metadata(line, manifest)
                continue

            if line.startswith("#"):
                continue

            manifest.files.append(line.replace("\\", "/"))

        return manifest

    @staticmethod
    def _parse_metadata(line: str, manifest: AddonManifest) -> None:
        content = line[2:].strip()

        if ":" not in content:
            return

        key, value = content.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        if key == "interface":
            manifest.interface = value
        elif key == "title":
            manifest.title = value
        elif key == "version":
            manifest.version = value
        elif key == "author":
            manifest.author = value
        elif key == "notes":
            manifest.notes = value
        elif key in {"savedvariables", "savedvariablespercharacter"}:
            manifest.saved_variables.extend(
                item.strip()
                for item in value.split(",")
                if item.strip()
            )
        elif key in {"dependencies", "dependson", "optionaldeps"}:
            manifest.dependencies.extend(
                item.strip()
                for item in value.split(",")
                if item.strip()
            )