from dataclasses import dataclass, field


@dataclass
class ASTNode:
    node_type: str
    text: str = ""

    start_line: int = 0
    end_line: int = 0

    children: list["ASTNode"] = field(default_factory=list)

    def add_child(self, child: "ASTNode") -> None:
        self.children.append(child)