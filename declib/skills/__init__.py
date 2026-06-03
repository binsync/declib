"""Bundled Agent Skills for declib.

Each subdirectory holds a SKILL.md (and any optional resources) that an LLM can
load to learn how to drive declib via the `decompiler` CLI. Use
`decompiler install-skill` to copy a skill into Claude Code or Codex.
"""
from pathlib import Path

SKILLS_DIR = Path(__file__).parent


def available_skills() -> list[str]:
    return sorted(
        p.name
        for p in SKILLS_DIR.iterdir()
        if p.is_dir() and (p / "SKILL.md").is_file()
    )


def skill_path(name: str) -> Path:
    path = SKILLS_DIR / name
    if not (path / "SKILL.md").is_file():
        raise FileNotFoundError(f"Unknown bundled skill: {name!r}")
    return path
