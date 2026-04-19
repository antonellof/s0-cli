"""Security-flavored env bootstrap.

The Meta-Harness paper §A.2 / B.3 documents that on TerminalBench-2 the winning
intervention was an env snapshot injected into the initial prompt — eliminating
2-5 wasted exploratory turns. We do the same trick, retargeted to security:
detect languages, package managers, lockfiles, frameworks, .git presence, CI
files, secrets-baseline files. The harness puts this snapshot at the top of
its system prompt so the agent doesn't waste turns running `ls` / `cat`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from s0_cli.targets.base import Target

LANG_HINTS: dict[str, list[str]] = {
    "python": ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg"],
    "javascript": ["package.json"],
    "typescript": ["tsconfig.json"],
    "go": ["go.mod"],
    "rust": ["Cargo.toml"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "ruby": ["Gemfile"],
    "php": ["composer.json"],
    "dotnet": ["*.csproj", "*.sln"],
    "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "kubernetes": ["*.yaml", "*.yml"],
    "terraform": ["*.tf"],
}

LOCKFILES = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock",
    "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
    "composer.lock",
]

FRAMEWORK_PROBES: dict[str, list[tuple[str, str]]] = {
    "django":   [("requirements.txt", "django"), ("pyproject.toml", "django"), ("manage.py", "")],
    "flask":    [("requirements.txt", "flask"), ("pyproject.toml", "flask")],
    "fastapi":  [("requirements.txt", "fastapi"), ("pyproject.toml", "fastapi")],
    "express":  [("package.json", "express")],
    "next":     [("package.json", "next")],
    "react":    [("package.json", "react")],
    "rails":    [("Gemfile", "rails")],
    "spring":   [("pom.xml", "spring"), ("build.gradle", "spring")],
}

CI_FILES = [
    ".github/workflows", ".gitlab-ci.yml", ".circleci/config.yml",
    "Jenkinsfile", "azure-pipelines.yml", ".drone.yml",
]

SECRETS_BASELINE = [
    ".secrets.baseline", ".gitleaks.toml", ".trufflehog-rules.yml",
]


@dataclass
class EnvSnapshot:
    languages: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    ci: list[str] = field(default_factory=list)
    has_git: bool = False
    has_secrets_baseline: bool = False
    file_count: int = 0
    top_level_entries: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines = ["[Environment Snapshot]"]
        lines.append(f"languages: {', '.join(self.languages) or 'unknown'}")
        if self.frameworks:
            lines.append(f"frameworks: {', '.join(self.frameworks)}")
        if self.lockfiles:
            lines.append(f"lockfiles: {', '.join(self.lockfiles)}")
        if self.ci:
            lines.append(f"ci: {', '.join(self.ci)}")
        lines.append(f"git: {'yes' if self.has_git else 'no'}")
        lines.append(
            f"secrets_baseline: {'yes' if self.has_secrets_baseline else 'no'}"
        )
        lines.append(f"files: {self.file_count}")
        if self.top_level_entries:
            lines.append("top_level: " + ", ".join(self.top_level_entries[:20]))
        if self.notes:
            lines.append("notes: " + " | ".join(self.notes))
        return "\n".join(lines)


async def env_snapshot(target: Target) -> EnvSnapshot:
    """Synchronous probe wrapped as async for harness ergonomics."""
    return _env_snapshot_sync(target)


def _env_snapshot_sync(target: Target) -> EnvSnapshot:
    root = target.root
    snap = EnvSnapshot()

    snap.has_git = (root / ".git").exists()

    top: list[str] = []
    file_count = 0
    for entry in sorted(root.iterdir()):
        if entry.name.startswith("."):
            continue
        top.append(entry.name + ("/" if entry.is_dir() else ""))
    snap.top_level_entries = top[:30]

    for p in root.rglob("*"):
        if "__pycache__" in p.parts or "node_modules" in p.parts:
            continue
        if any(part.startswith(".") for part in p.parts):
            continue
        if p.is_file():
            file_count += 1
            if file_count > 5000:
                snap.notes.append("file count >5000, scan capped")
                break
    snap.file_count = file_count

    detected_langs: set[str] = set()
    for lang, names in LANG_HINTS.items():
        for n in names:
            if "*" in n:
                if any(root.rglob(n)):
                    detected_langs.add(lang)
            elif (root / n).exists():
                detected_langs.add(lang)
    snap.languages = sorted(detected_langs)

    found_locks: list[str] = []
    for lock in LOCKFILES:
        if (root / lock).exists():
            found_locks.append(lock)
    snap.lockfiles = found_locks

    detected_fw: set[str] = set()
    for fw, probes in FRAMEWORK_PROBES.items():
        for filename, needle in probes:
            target_file = root / filename
            if not target_file.exists():
                continue
            if not needle:
                detected_fw.add(fw)
                continue
            try:
                txt = target_file.read_text(encoding="utf-8", errors="replace").lower()
                if needle.lower() in txt:
                    detected_fw.add(fw)
            except OSError:
                continue
    snap.frameworks = sorted(detected_fw)

    snap.ci = [c for c in CI_FILES if (root / c).exists()]
    snap.has_secrets_baseline = any((root / s).exists() for s in SECRETS_BASELINE)

    return snap
