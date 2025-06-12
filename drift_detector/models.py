from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence


class Severity(str, Enum):
    CRITICAL = "critical"
    MEDIUM = "medium"
    LOW = "low"


class ChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"


@dataclass
class FunctionSignature:
    name: str
    signature: str
    has_docstring: bool
    lineno: Optional[int] = None
    docstring: Optional[str] = None


@dataclass
class CodeChange:
    file_path: str
    language: str
    change_type: ChangeType
    summary: str
    symbol: Optional[str] = None
    old_signature: Optional[FunctionSignature] = None
    new_signature: Optional[FunctionSignature] = None
    old_code: Optional[str] = None
    new_code: Optional[str] = None


@dataclass
class DocumentationReference:
    file_path: str
    snippet: str
    changed: bool


class DriftType(str, Enum):
    MISSING_DOCSTRING = "missing_docstring"
    OUTDATED_SIGNATURE = "outdated_signature"
    REMOVED_FEATURE = "removed_feature"
    OUTDATED_EXAMPLE = "outdated_example"
    GENERAL_DRIFT = "general_drift"


@dataclass
class DriftCandidate:
    change: CodeChange
    drift_type: DriftType
    description: str
    documentation: Sequence[DocumentationReference] = field(default_factory=list)


@dataclass
class DriftIssue:
    drift_type: DriftType
    severity: Severity
    file_path: str
    summary: str
    suggestion: str
    code_snippet: str
    documentation_snippet: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class DriftReport:
    issues: List[DriftIssue] = field(default_factory=list)

    def summary(self) -> str:
        by_severity = {level: 0 for level in Severity}
        for issue in self.issues:
            by_severity[issue.severity] += 1
        total = len(self.issues)
        parts = [f"{total} issues detected"]
        for severity in Severity:
            count = by_severity[severity]
            if count:
                parts.append(f"{count} {severity.value}")
        return ", ".join(parts)


@dataclass
class RepositoryChanges:
    changes: List[CodeChange] = field(default_factory=list)
    documentation_files_changed: set[str] = field(default_factory=set)
    all_changed_files: set[str] = field(default_factory=set)

