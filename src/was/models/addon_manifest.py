from dataclasses import dataclass, field


@dataclass
class AddonManifest:
    interface: str = ""
    title: str = ""
    version: str = ""
    author: str = ""
    notes: str = ""

    saved_variables: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)