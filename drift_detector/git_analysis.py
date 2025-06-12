from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from git import Commit, DiffIndex, Repo

from .models import ChangeType, CodeChange, FunctionSignature, RepositoryChanges

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    signature: FunctionSignature
    source: str


class GitAnalyzer:
    def __init__(self, repo_path: Path):
        self.repo = Repo(repo_path)

    def collect_changes(
        self,
        *,
        from_ref: Optional[str] = None,
        to_ref: Optional[str] = None,
        since: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> RepositoryChanges:
        base_commit, target_commit = self._resolve_commit_range(
            from_ref=from_ref, to_ref=to_ref, since=since, branch=branch
        )
        diff = base_commit.diff(target_commit, create_patch=True)

        repository_changes = RepositoryChanges()
        repository_changes.all_changed_files = {
            d.a_path or d.b_path for d in diff if (d.a_path or d.b_path)
        }

        for diff_item in diff:
            file_path = diff_item.b_path or diff_item.a_path
            if not file_path:
                continue

            change_type = _map_change_type(diff_item.change_type)
            if change_type is None:
                continue

            if _looks_like_documentation(file_path):
                repository_changes.documentation_files_changed.add(file_path)

            language = _infer_language(file_path)
            old_source = _blob_to_text(diff_item.a_blob)
            new_source = _blob_to_text(diff_item.b_blob)

            if language == "python":
                py_changes = self._collect_python_changes(
                    file_path=file_path,
                    change_type=change_type,
                    old_source=old_source,
                    new_source=new_source,
                )
                repository_changes.changes.extend(py_changes)
                continue

            summary = f"{change_type.value.title()} {file_path}"
            repository_changes.changes.append(
                CodeChange(
                    file_path=file_path,
                    language=language,
                    change_type=change_type,
                    summary=summary,
                    old_code=old_source,
                    new_code=new_source,
                )
            )

        return repository_changes

    def _collect_python_changes(
        self,
        *,
        file_path: str,
        change_type: ChangeType,
        old_source: Optional[str],
        new_source: Optional[str],
    ) -> Iterable[CodeChange]:
        if change_type == ChangeType.REMOVED:
            old_functions = _parse_python_functions(old_source)
            for qualname, info in old_functions.items():
                yield CodeChange(
                    file_path=file_path,
                    language="python",
                    change_type=ChangeType.REMOVED,
                    summary=f"Function {qualname} removed",
                    symbol=qualname,
                    old_signature=info.signature,
                    old_code=info.source,
                )
            return

        old_functions = _parse_python_functions(old_source)
        new_functions = _parse_python_functions(new_source)

        for qualname, info in new_functions.items():
            if qualname not in old_functions:
                summary = f"Function {qualname} added"
                yield CodeChange(
                    file_path=file_path,
                    language="python",
                    change_type=ChangeType.ADDED,
                    summary=summary,
                    symbol=qualname,
                    new_signature=info.signature,
                    new_code=info.source,
                )
                continue

            previous = old_functions[qualname]
            if info.signature.signature != previous.signature.signature:
                summary = (
                    f"Function {qualname} signature changed from "
                    f"{previous.signature.signature} to {info.signature.signature}"
                )
                yield CodeChange(
                    file_path=file_path,
                    language="python",
                    change_type=ChangeType.MODIFIED,
                    summary=summary,
                    symbol=qualname,
                    old_signature=previous.signature,
                    new_signature=info.signature,
                    old_code=previous.source,
                    new_code=info.source,
                )
            elif info.signature.has_docstring != previous.signature.has_docstring:
                summary = (
                    f"Function {qualname} docstring "
                    f"{'added' if info.signature.has_docstring else 'removed'}"
                )
                yield CodeChange(
                    file_path=file_path,
                    language="python",
                    change_type=ChangeType.MODIFIED,
                    summary=summary,
                    symbol=qualname,
                    old_signature=previous.signature,
                    new_signature=info.signature,
                    old_code=previous.source,
                    new_code=info.source,
                )

        for qualname, previous in old_functions.items():
            if qualname not in new_functions:
                summary = f"Function {qualname} removed"
                yield CodeChange(
                    file_path=file_path,
                    language="python",
                    change_type=ChangeType.REMOVED,
                    summary=summary,
                    symbol=qualname,
                    old_signature=previous.signature,
                    old_code=previous.source,
                )

    def _resolve_commit_range(
        self,
        *,
        from_ref: Optional[str],
        to_ref: Optional[str],
        since: Optional[str],
        branch: Optional[str],
    ) -> Tuple[Commit, Commit]:
        if from_ref and to_ref:
            return self.repo.commit(from_ref), self.repo.commit(to_ref)

        head_commit = self.repo.head.commit

        if branch:
            target = self.repo.commit(branch)
            base = head_commit
            return base, target

        if since:
            base = self.repo.commit(since)
            return base, head_commit

        parents = head_commit.parents
        if not parents:
            return head_commit, head_commit
        return parents[0], head_commit


def _map_change_type(change_type: str) -> Optional[ChangeType]:
    mapping = {
        "A": ChangeType.ADDED,
        "M": ChangeType.MODIFIED,
        "D": ChangeType.REMOVED,
        "R": ChangeType.MODIFIED,
        "T": ChangeType.MODIFIED,
    }
    return mapping.get(change_type.upper())


def _looks_like_documentation(path: str) -> bool:
    lowered = path.lower()
    if "docs/" in lowered or "doc/" in lowered:
        return True
    return lowered.endswith((".md", ".rst", ".adoc")) or "readme" in lowered


def _infer_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".md", ".rst"}:
        return "markdown"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    return suffix.lstrip(".") or "text"


def _blob_to_text(blob) -> Optional[str]:
    if blob is None:
        return None
    stream = blob.data_stream
    data = stream.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def _parse_python_functions(source: Optional[str]) -> Dict[str, FunctionInfo]:
    if not source:
        return {}

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        logger.warning("Failed to parse Python file for functions: %s", exc)
        return {}

    functions: Dict[str, FunctionInfo] = {}

    for qualname, node in _iter_function_defs(tree):
        docstring = ast.get_docstring(node)
        signature = FunctionSignature(
            name=qualname,
            signature=_format_signature(node),
            has_docstring=docstring is not None and docstring.strip() != "",
            lineno=node.lineno,
            docstring=docstring,
        )
        source_segment = ast.get_source_segment(source, node) or ""
        functions[qualname] = FunctionInfo(signature=signature, source=source_segment)

    return functions


def _iter_function_defs(
    node: ast.AST, parents: Optional[Iterable[str]] = None
) -> Iterable[Tuple[str, ast.AST]]:
    if parents is None:
        parents = []

    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = ".".join([*parents, child.name])
            yield qualname, child
            yield from _iter_function_defs(child, [*parents, child.name])
        elif isinstance(child, ast.ClassDef):
            yield from _iter_function_defs(child, [*parents, child.name])
        else:
            yield from _iter_function_defs(child, parents)


def _format_signature(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        try:
            args = ast.unparse(node.args)
        except AttributeError:  # pragma: no cover - fallback for older Python
            args = ", ".join(arg.arg for arg in node.args.args)
        prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
        returns = ""
        if getattr(node, "returns", None) is not None:
            try:
                returns = f" -> {ast.unparse(node.returns)}"
            except AttributeError:  # pragma: no cover
                returns = ""
        return f"{prefix}{node.name}({args}){returns}"
    return ""

