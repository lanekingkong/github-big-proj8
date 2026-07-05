"""
CodeGuardian Security Scanner — static analysis and vulnerability detection.

Performs SAST (Static Application Security Testing) on source code,
detecting common vulnerability patterns, insecure configurations,
and dependency risks.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional

from codeguardian.core.models import (
    FileLanguage,
    Severity,
    Vulnerability,
    VulnerabilityCategory,
)

# ── Vulnerability Pattern Database ────────────────────────────────────

VULN_PATTERNS: list[dict] = [
    {
        "id": "CG-SQL-001",
        "category": VulnerabilityCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Potential SQL Injection",
        "description": "String formatting in SQL query may allow SQL injection attacks.",
        "pattern": re.compile(
            r'(?:execute|cursor\.execute|raw)\s*\(?\s*(?:f["\']|["\'].*%.*["\'].*%)',
            re.IGNORECASE,
        ),
        "recommendation": "Use parameterized queries with placeholders instead of string formatting.",
        "cwe_id": "CWE-89",
        "languages": [FileLanguage.PYTHON, FileLanguage.JAVA, FileLanguage.PHP, FileLanguage.GO],
    },
    {
        "id": "CG-HARD-001",
        "category": VulnerabilityCategory.SENSITIVE_DATA,
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Secret / Credential",
        "description": "Password, API key, or token appears to be hardcoded in source code.",
        "pattern": re.compile(
            r'(?:password|passwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*["\'][^\'"]{8,}["\']',
            re.IGNORECASE,
        ),
        "recommendation": "Use environment variables or a secret manager (Vault, AWS Secrets Manager).",
        "cwe_id": "CWE-798",
        "languages": list(FileLanguage),
    },
    {
        "id": "CG-XSS-001",
        "category": VulnerabilityCategory.XSS,
        "severity": Severity.HIGH,
        "title": "Potential Cross-Site Scripting (XSS)",
        "description": "User input rendered directly into HTML without sanitization.",
        "pattern": re.compile(
            r'(?:innerHTML|dangerouslySetInnerHTML|document\.write)\s*[=(]',
            re.IGNORECASE,
        ),
        "recommendation": "Use textContent or a sanitization library like DOMPurify.",
        "cwe_id": "CWE-79",
        "languages": [FileLanguage.JAVASCRIPT, FileLanguage.TYPESCRIPT],
    },
    {
        "id": "CG-EVAL-001",
        "category": VulnerabilityCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Use of eval() / exec()",
        "description": "Dynamic code execution with eval() or exec() is extremely dangerous.",
        "pattern": re.compile(r'\b(?:eval|exec)\s*\(', re.IGNORECASE),
        "recommendation": "Avoid eval/exec entirely. Use safe alternatives like ast.literal_eval().",
        "cwe_id": "CWE-95",
        "languages": [FileLanguage.PYTHON, FileLanguage.JAVASCRIPT, FileLanguage.TYPESCRIPT, FileLanguage.PHP],
    },
    {
        "id": "CG-PATH-001",
        "category": VulnerabilityCategory.INJECTION,
        "severity": Severity.HIGH,
        "title": "Potential Path Traversal",
        "description": "User-controlled path concatenation may allow directory traversal.",
        "pattern": re.compile(r'os\.path\.join\s*\(\s*[^,]+,\s*(?:request|input|user|param|query)', re.IGNORECASE),
        "recommendation": "Validate and sanitize user input; use pathlib with resolve().",
        "cwe_id": "CWE-22",
        "languages": [FileLanguage.PYTHON],
    },
    {
        "id": "CG-DESER-001",
        "category": VulnerabilityCategory.DESERIALIZATION,
        "severity": Severity.CRITICAL,
        "title": "Insecure Deserialization",
        "description": "Using pickle/yaml.load on untrusted data can lead to RCE.",
        "pattern": re.compile(r'\b(?:pickle\.loads?|yaml\.load\s*\()', re.IGNORECASE),
        "recommendation": "Use yaml.safe_load() instead of yaml.load(); avoid pickle with untrusted data.",
        "cwe_id": "CWE-502",
        "languages": [FileLanguage.PYTHON],
    },
    {
        "id": "CG-DEP-001",
        "category": VulnerabilityCategory.DEPENDENCY,
        "severity": Severity.MEDIUM,
        "title": "Unpinned Dependency Version",
        "description": "Dependency specified without a pinned version, risking supply chain attacks.",
        "pattern": re.compile(r'(?:requirements\.txt|pyproject\.toml|package\.json)', re.IGNORECASE),
        "recommendation": "Pin dependency versions with exact hashes where possible.",
        "cwe_id": "CWE-1104",
        "languages": list(FileLanguage),
    },
    {
        "id": "CG-LOG-001",
        "category": VulnerabilityCategory.SENSITIVE_DATA,
        "severity": Severity.MEDIUM,
        "title": "Sensitive Data in Logs",
        "description": "Logging statements may include passwords, tokens, or credentials.",
        "pattern": re.compile(
            r'(?:log|logger|logging)\.\w+\s*\(.*(?:password|token|secret|key|credential)',
            re.IGNORECASE,
        ),
        "recommendation": "Redact sensitive fields before logging; use structured logging with filters.",
        "cwe_id": "CWE-532",
        "languages": list(FileLanguage),
    },
]


class SecurityScanner:
    """Scans source code files for security vulnerabilities using pattern matching.

    Usage:
        scanner = SecurityScanner()
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="app.py")
        for v in vulns:
            print(f"[{v.severity.value}] {v.title}")
    """

    def __init__(self, custom_patterns: Optional[list[dict]] = None) -> None:
        self._patterns = list(VULN_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)

    def scan_text(
        self,
        code: str,
        *,
        language: FileLanguage = FileLanguage.OTHER,
        file_path: str = "",
    ) -> list[Vulnerability]:
        """Scan a code string and return detected vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        lines = code.split("\n")

        for pattern_def in self._patterns:
            allowed_langs = pattern_def.get("languages", [])
            if language not in allowed_langs and language != FileLanguage.OTHER:
                continue

            for match in pattern_def["pattern"].finditer(code):
                start_pos = match.start()
                line_start = code[:start_pos].count("\n") + 1
                snippet = match.group(0)

                vuln_id = hashlib.sha256(
                    f"{pattern_def['id']}:{file_path}:{line_start}".encode()
                ).hexdigest()[:12]

                vulnerabilities.append(
                    Vulnerability(
                        id=f"{pattern_def['id']}-{vuln_id}",
                        category=pattern_def["category"],
                        severity=pattern_def["severity"],
                        title=pattern_def["title"],
                        description=pattern_def.get("description", ""),
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start + snippet.count("\n"),
                        code_snippet=snippet[:200],
                        recommendation=pattern_def.get("recommendation", ""),
                        cwe_id=pattern_def.get("cwe_id"),
                    )
                )

        return sorted(vulnerabilities, key=lambda v: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[v.severity.value]
        ))

    def scan_file(self, file_path: str) -> list[Vulnerability]:
        """Scan a single file and return detected vulnerabilities."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        code = p.read_text(encoding="utf-8", errors="replace")
        language = self._detect_language(file_path)
        return self.scan_text(code, language=language, file_path=file_path)

    def scan_directory(self, directory: str, *, recursive: bool = True) -> list[Vulnerability]:
        """Recursively scan all code files in a directory."""
        all_vulns: list[Vulnerability] = []
        dir_path = Path(directory)

        code_extensions = {
            ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
            ".cpp", ".c", ".h", ".cs", ".rb", ".php", ".swift", ".kt",
            ".sql", ".sh", ".bash", ".yaml", ".yml", ".toml", ".env",
        }

        for file_path in dir_path.rglob("*" if recursive else "[!.]*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in code_extensions:
                continue
            # Skip common non-code directories
            parts = set(file_path.parts)
            if parts & {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}:
                continue
            try:
                all_vulns.extend(self.scan_file(str(file_path)))
            except Exception:
                continue

        return all_vulns

    @staticmethod
    def _detect_language(file_path: str) -> FileLanguage:
        ext = Path(file_path).suffix.lower()
        mapping: dict[str, FileLanguage] = {
            ".py": FileLanguage.PYTHON,
            ".js": FileLanguage.JAVASCRIPT,
            ".ts": FileLanguage.TYPESCRIPT,
            ".tsx": FileLanguage.TYPESCRIPT,
            ".jsx": FileLanguage.JAVASCRIPT,
            ".go": FileLanguage.GO,
            ".rs": FileLanguage.RUST,
            ".java": FileLanguage.JAVA,
            ".cpp": FileLanguage.CPP,
            ".c": FileLanguage.CPP,
            ".h": FileLanguage.CPP,
            ".cs": FileLanguage.CSHARP,
            ".rb": FileLanguage.RUBY,
            ".php": FileLanguage.PHP,
            ".swift": FileLanguage.SWIFT,
            ".kt": FileLanguage.KOTLIN,
            ".sql": FileLanguage.SQL,
            ".sh": FileLanguage.SHELL,
            ".bash": FileLanguage.SHELL,
            ".yaml": FileLanguage.YAML,
            ".yml": FileLanguage.YAML,
            ".dockerfile": FileLanguage.DOCKERFILE,
        }
        return mapping.get(ext, FileLanguage.OTHER)
