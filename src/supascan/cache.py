from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

from .models import Credentials

CACHE_DIR = Path.home() / ".supascan"
CACHE_FILE = CACHE_DIR / "cache.json"


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(data, indent=2))


def add_credentials(creds: Credentials) -> None:
    cache = load_cache()
    cache[creds.project_ref] = {
        "project_ref": creds.project_ref,
        "anon_key": creds.anon_key,
        "user_token": creds.user_token,
        "source": creds.source,
    }
    save_cache(cache)


def get_credentials(project_ref: str) -> Optional[Credentials]:
    cache = load_cache()
    entry = cache.get(project_ref)
    if not entry:
        return None
    return Credentials(
        project_ref=entry["project_ref"],
        anon_key=entry["anon_key"],
        user_token=entry.get("user_token"),
        source=entry.get("source"),
    )


def list_all() -> list[Credentials]:
    cache = load_cache()
    result = []
    for entry in cache.values():
        result.append(
            Credentials(
                project_ref=entry["project_ref"],
                anon_key=entry["anon_key"],
                user_token=entry.get("user_token"),
                source=entry.get("source"),
            )
        )
    return result


def remove(project_ref: str) -> bool:
    cache = load_cache()
    if project_ref not in cache:
        return False
    del cache[project_ref]
    save_cache(cache)
    return True


def clear() -> int:
    cache = load_cache()
    count = len(cache)
    save_cache({})
    return count
