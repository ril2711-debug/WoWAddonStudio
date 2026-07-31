from was.ast.ast_node import ASTNode


class AST:

    def __init__(self):
        self.root: ASTNode | None = None

    def set_root(self, node: ASTNode):
        self.root = node