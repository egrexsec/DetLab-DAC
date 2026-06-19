from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs

DEFAULT_SOURCE_REF = "main"
DEFAULT_SOURCE_SUBDIR = "detections"
DEFAULT_CACHE_ROOT = Path(os.getenv("DETLAB_CACHE_DIR", ".detlab/cache/github"))
GITHUB_SPEC_PREFIX = "github://"


@dataclass(frozen=True)
class DetectionSource:
    mode: str
    repo_url: str | None = None
    ref: str | None = None
    subdir: str | None = None


class DetectionSourceError(RuntimeError):
    pass


def _normalize_repo_url(repo: str) -> str:
    if repo.startswith(("https://", "http://", "git@")):
        return repo[:-4] + ".git" if repo.startswith(("https://", "http://")) and not repo.endswith(".git") else repo
    return f"https://github.com/{repo}.git"


def parse_github_source_spec(spec: str) -> DetectionSource:
    if not spec.startswith(GITHUB_SPEC_PREFIX):
        raise DetectionSourceError(f"Unsupported detection source spec: {spec}")

    body = spec[len(GITHUB_SPEC_PREFIX) :]
    path_part, _, query = body.partition("?")
    segments = [segment for segment in path_part.split("/") if segment]
    if len(segments) < 3:
        raise DetectionSourceError(
            "GitHub source spec must look like github://owner/repo/path/to/detections?ref=main"
        )

    repo = "/".join(segments[:2])
    subdir = "/".join(segments[2:])
    params = parse_qs(query)
    ref = params.get("ref", [DEFAULT_SOURCE_REF])[0]
    return DetectionSource(mode="github", repo_url=_normalize_repo_url(repo), ref=ref, subdir=subdir)


def source_from_environment() -> DetectionSource | None:
    repo = os.getenv("DETLAB_SOURCE_REPO")
    if not repo:
        return None

    return DetectionSource(
        mode="github",
        repo_url=_normalize_repo_url(repo),
        ref=os.getenv("DETLAB_SOURCE_REF", DEFAULT_SOURCE_REF),
        subdir=os.getenv("DETLAB_SOURCE_SUBDIR", DEFAULT_SOURCE_SUBDIR),
    )


def _cache_checkout_dir(source: DetectionSource, cache_root: Path = DEFAULT_CACHE_ROOT) -> Path:
    if not source.repo_url or not source.ref:
        raise DetectionSourceError("GitHub detection source requires repo_url and ref")

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", source.repo_url.replace(".git", ""))
    ref_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", source.ref)
    return cache_root / f"{slug}-{ref_slug}"


def sync_github_source(source: DetectionSource, cache_root: Path = DEFAULT_CACHE_ROOT) -> Path:
    if source.mode != "github":
        raise DetectionSourceError(f"Unsupported source mode for sync: {source.mode}")
    if not source.repo_url or not source.ref or not source.subdir:
        raise DetectionSourceError("GitHub detection source requires repo_url, ref, and subdir")

    checkout_dir = _cache_checkout_dir(source, cache_root)
    checkout_dir.parent.mkdir(parents=True, exist_ok=True)

    if (checkout_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(checkout_dir), "fetch", "--depth", "1", "origin", source.ref],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(checkout_dir), "checkout", "--force", "FETCH_HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", source.ref, source.repo_url, str(checkout_dir)],
            check=True,
            capture_output=True,
            text=True,
        )

    detection_dir = checkout_dir / source.subdir
    if not detection_dir.exists():
        raise DetectionSourceError(
            f"Detection directory not found after sync: {detection_dir}"
        )
    return detection_dir


def resolve_detection_dir(path: str | Path = DEFAULT_SOURCE_SUBDIR, cache_root: Path = DEFAULT_CACHE_ROOT) -> Path:
    env_source = source_from_environment()
    normalized_path = str(path)
    if env_source and normalized_path in {".", "", DEFAULT_SOURCE_SUBDIR}:
        subdir = env_source.subdir
        return sync_github_source(
            DetectionSource(
                mode="github",
                repo_url=env_source.repo_url,
                ref=env_source.ref,
                subdir=subdir,
            ),
            cache_root,
        )

    candidate = Path(path)
    if candidate.exists():
        return candidate

    if isinstance(path, str) and path.startswith(GITHUB_SPEC_PREFIX):
        return sync_github_source(parse_github_source_spec(path), cache_root)

    if env_source:
        return sync_github_source(
            DetectionSource(
                mode="github",
                repo_url=env_source.repo_url,
                ref=env_source.ref,
                subdir=normalized_path,
            ),
            cache_root,
        )

    return candidate


def describe_detection_source(path: str | Path = DEFAULT_SOURCE_SUBDIR) -> dict[str, str | bool | None]:
    env_source = source_from_environment()
    normalized_path = str(path)
    if env_source and normalized_path in {".", "", DEFAULT_SOURCE_SUBDIR}:
        resolved = resolve_detection_dir(path)
        return {
            "mode": env_source.mode,
            "repo_url": env_source.repo_url,
            "ref": env_source.ref,
            "subdir": env_source.subdir,
            "resolved_path": str(resolved.resolve()),
            "synced": True,
        }

    candidate = Path(path)
    if candidate.exists():
        return {
            "mode": "local",
            "repo_url": None,
            "ref": None,
            "subdir": str(candidate),
            "resolved_path": str(candidate.resolve()),
            "synced": False,
        }

    if isinstance(path, str) and path.startswith(GITHUB_SPEC_PREFIX):
        source = parse_github_source_spec(path)
        resolved = sync_github_source(source)
        return {
            "mode": source.mode,
            "repo_url": source.repo_url,
            "ref": source.ref,
            "subdir": source.subdir,
            "resolved_path": str(resolved.resolve()),
            "synced": True,
        }

    if env_source:
        resolved = resolve_detection_dir(path)
        return {
            "mode": env_source.mode,
            "repo_url": env_source.repo_url,
            "ref": env_source.ref,
            "subdir": normalized_path,
            "resolved_path": str(resolved.resolve()),
            "synced": True,
        }

    return {
        "mode": "local",
        "repo_url": None,
        "ref": None,
        "subdir": str(candidate),
        "resolved_path": str(candidate),
        "synced": False,
    }
