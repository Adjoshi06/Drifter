from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from .models import DocumentationReference

logger = logging.getLogger(__name__)


class DocumentationFinder:
    """Locate documentation snippets that reference given symbols."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    def build_index(self) -> None:
        # Trigger cache population
        _ = self._documentation_files()

    def references_for_symbol(
        self, symbol: str, *, changed_docs: Sequence[str]
    ) -> List[DocumentationReference]:
        references: List[DocumentationReference] = []
        symbol_lower = symbol.lower()

        for doc_path in self._documentation_files():
            try:
                text = doc_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = doc_path.read_text(encoding="utf-8", errors="ignore")
            except FileNotFoundError:
                continue

            if symbol_lower not in text.lower():
                continue

            snippet = _extract_snippet(text, symbol)
            relative_path = str(doc_path.relative_to(self.repo_path))
            references.append(
                DocumentationReference(
                    file_path=relative_path,
                    snippet=snippet,
                    changed=relative_path in changed_docs,
                )
            )

        return references

    @lru_cache(maxsize=1)
    def _documentation_files(self) -> Iterable[Path]:
        patterns = ("README.md", "README.rst", "*.md", "*.rst", "*.adoc")
        doc_roots = ["docs", "doc", "documentation", "examples", "samples"]

        files: Dict[str, Path] = {}

        for pattern in patterns:
            for path in self.repo_path.rglob(pattern):
                if path.is_file():
                    files[str(path)] = path

        for root in doc_roots:
            root_path = self.repo_path / root
            if not root_path.exists():
                continue
            for path in root_path.rglob("*"):
                if path.is_file() and _is_text_file(path):
                    files[str(path)] = path

        return list(files.values())


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in {".md", ".rst", ".txt", ".adoc", ".py", ".js", ".ts"}


def _extract_snippet(text: str, symbol: str, context_lines: int = 5) -> str:
    lowered = text.lower()
    symbol_lower = symbol.lower()
    index = lowered.find(symbol_lower)
    if index == -1:
        return text[: min(400, len(text))]

    before = text[:index].splitlines()
    after = text[index:].splitlines()

    snippet_lines = before[-context_lines:] + after[: context_lines + 1]
    snippet = "\n".join(snippet_lines)

    max_len = 600
    return snippet[:max_len]

