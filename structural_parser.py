"""
Language-aware structural node extraction for Layer 4 (Structural Drift).

Python uses stdlib ast (always available, no extra dep). All other languages
use tree-sitter grammar packages and a recursive node walker — no query-string
API, so it works across tree-sitter versions.

If a grammar package is not installed the file is silently skipped.

Supported:  .py  .js  .jsx  .ts  .tsx  .go  .rs  .java
"""

import ast
from pathlib import Path
from typing import Optional

_EXT_TO_LANG: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "tsx",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
}

_JS_RULES: dict[str, str] = {
    "function_declaration": "name",
    "class_declaration":    "name",
    "method_definition":    "name",
}
_LANG_RULES: dict[str, dict[str, str]] = {
    "javascript": _JS_RULES,
    "typescript": {**_JS_RULES,
                   "interface_declaration":    "name",
                   "type_alias_declaration":   "name"},
    "go": {
        "function_declaration": "name",
        "method_declaration":   "name",
        "type_spec":            "name",
        "const_spec":           "name",
    },
    "rust": {
        "function_item": "name",
        "struct_item":   "name",
        "enum_item":     "name",
        "trait_item":    "name",
        "const_item":    "name",
        "static_item":   "name",
    },
    "java": {
        "class_declaration":     "name",
        "interface_declaration": "name",
        "enum_declaration":      "name",
        "method_declaration":    "name",
    },
}
_LANG_RULES["tsx"] = _LANG_RULES["typescript"]


def language_for_path(path: str) -> Optional[str]:
    return _EXT_TO_LANG.get(Path(path).suffix.lower())


def _load_language(lang_key: str):
    try:
        from tree_sitter import Language
        if lang_key == "python":
            import tree_sitter_python as m
            return Language(m.language())
        if lang_key in ("javascript",):
            import tree_sitter_javascript as m
            return Language(m.language())
        if lang_key == "typescript":
            import tree_sitter_typescript as m
            return Language(m.language_typescript())
        if lang_key == "tsx":
            import tree_sitter_typescript as m
            return Language(m.language_tsx())
        if lang_key == "go":
            import tree_sitter_go as m
            return Language(m.language())
        if lang_key == "rust":
            import tree_sitter_rust as m
            return Language(m.language())
        if lang_key == "java":
            import tree_sitter_java as m
            return Language(m.language())
    except (ImportError, AttributeError):
        pass
    return None


def _collect(node, rules: dict[str, str], names: set[str]) -> None:
    name_field = rules.get(node.type)
    if name_field:
        name_node = node.child_by_field_name(name_field)
        if name_node and name_node.text:
            names.add(name_node.text.decode("utf-8"))
    elif node.type == "variable_declarator" and "function_declaration" in rules:
        # Track all named JS/TS declarations: arrow functions, constants,
        # config objects, auth literals — anything with a name at declarator level.
        name_node = node.child_by_field_name("name")
        if name_node and name_node.text:
            names.add(name_node.text.decode("utf-8"))
    for child in node.children:
        _collect(child, rules, names)


def _extract_via_treesitter(source: str, lang_key: str) -> set[str]:
    ts_lang = _load_language(lang_key)
    if ts_lang is None:
        return set()
    from tree_sitter import Parser
    parser = Parser(ts_lang)
    tree = parser.parse(bytes(source, "utf-8"))
    names: set[str] = set()
    _collect(tree.root_node, _LANG_RULES[lang_key], names)
    return names


def extract_named_nodes(source: str, path: str) -> set[str]:
    lang_key = language_for_path(path)
    if lang_key is None:
        return set()
    if lang_key == "python":
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            raise ValueError(f"SyntaxError: {e}") from e
        except (RecursionError, MemoryError):
            return set()
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
        return names
    try:
        return _extract_via_treesitter(source, lang_key)
    except Exception as e:
        raise ValueError(str(e)) from e
