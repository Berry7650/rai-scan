"""Conservative discovery of AI-related data not owned by a known signature."""

from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

from rai_scan.classifier.size import disk_usage
from rai_scan.models import Artifact


NAME_MARKERS = {
    "ai",
    "agent",
    "agents",
    "anthropic",
    "bedrock",
    "chatgpt",
    "claude",
    "codeium",
    "copilot",
    "diffusion",
    "embedding",
    "embeddings",
    "gemini",
    "gpt",
    "huggingface",
    "langchain",
    "llama",
    "llm",
    "mcp",
    "modelscope",
    "ollama",
    "openai",
    "opentui",
    "semantic",
    "transformers",
    "vllm",
}

MODEL_SUFFIXES = {
    ".gguf",
    ".ggml",
    ".onnx",
    ".safetensors",
    ".tflite",
}

MODEL_FILENAMES = {
    "adapter_config.json",
    "tokenizer.json",
    "tokenizer_config.json",
}


def _tokens(name: str) -> Set[str]:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    return {part for part in normalized.split("_") if part}


def _name_reason(path: Path) -> str:
    matched = sorted(_tokens(path.name) & NAME_MARKERS)
    return "name:" + ",".join(matched) if matched else ""


def _model_reason(path: Path) -> str:
    """Inspect a bounded sample, avoiding a recursive size-like second walk."""
    if not path.is_dir():
        return ""
    checked = 0
    stack: List[Tuple[Path, int]] = [(path, 0)]
    while stack and checked < 300:
        current, depth = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            checked += 1
            lowered = entry.name.lower()
            if entry.is_file() and (
                entry.suffix.lower() in MODEL_SUFFIXES or lowered in MODEL_FILENAMES
            ):
                return "model-file:" + entry.name
            if entry.is_dir() and depth < 2:
                stack.append((entry, depth + 1))
            if checked >= 300:
                break
    return ""


def _known_paths(signatures: Dict[str, Any]) -> Set[Path]:
    home = Path.home()
    paths = set()
    for signature in signatures["agents"].values():
        for field in ("binary_paths", "config_dirs", "cache_dirs"):
            for value in signature.get(field, []):
                path = Path(value).expanduser()
                paths.add(path if path.is_absolute() else home / path)
        for field in ("config_globs", "cache_globs"):
            for value in signature.get(field, []):
                pattern = Path(value).expanduser()
                pattern = pattern if pattern.is_absolute() else home / pattern
                paths.update(pattern.parent.glob(pattern.name))
    return paths


def _candidate_roots() -> Iterable[Tuple[Path, str]]:
    home = Path.home()
    yield home, "ai_related"
    yield home / ".local/bin", "ai_related_binary"
    yield home / "bin", "ai_related_binary"
    yield home / ".cargo/bin", "ai_related_binary"
    yield home / ".npm-global/bin", "ai_related_binary"
    yield home / ".config", "ai_related_config"
    yield home / ".cache", "ai_related_cache"
    yield home / ".local/share", "ai_related_data"
    yield home / ".local/state", "ai_related_state"


def scan(signatures: Dict[str, Any], already_matched: Iterable[Artifact]) -> List[Artifact]:
    known = _known_paths(signatures)
    known.update(Path(item.path) for item in already_matched)
    found: List[Artifact] = []
    seen: Set[str] = set()

    for root, kind in _candidate_roots():
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for path in children:
            if root == Path.home() and not path.name.startswith("."):
                continue
            if any(item == path or item in path.parents or path in item.parents for item in known):
                continue
            reason = _name_reason(path)
            if not reason:
                reason = _model_reason(path)
            if not reason:
                continue
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                stat = path.lstat()
            except OSError:
                continue
            found.append(
                Artifact(
                    path=key,
                    type=kind,
                    size_bytes=disk_usage(path),
                    mtime=stat.st_mtime,
                    agent_hint=reason,
                )
            )
    return sorted(found, key=lambda item: item.path)
