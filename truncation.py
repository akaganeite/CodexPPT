"""Head/tail text truncation utilities for bounded observations."""

from __future__ import annotations

from typing import Any


def byte_len(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def text_head_tail(text: str, max_chars: int) -> dict[str, Any]:
    if max_chars <= 0:
        return {
            "head": "",
            "tail": "",
            "truncated": bool(text),
            "omitted_bytes": byte_len(text),
            "omitted_chars": len(text),
            "original_bytes": byte_len(text),
            "original_chars": len(text),
            "retained_bytes": 0,
            "retained_chars": 0,
        }
    if len(text) <= max_chars:
        return {
            "head": text,
            "tail": "",
            "truncated": False,
            "omitted_bytes": 0,
            "omitted_chars": 0,
            "original_bytes": byte_len(text),
            "original_chars": len(text),
            "retained_bytes": byte_len(text),
            "retained_chars": len(text),
        }
    head_budget = max_chars // 2
    tail_budget = max_chars - head_budget
    head = text[:head_budget]
    tail = text[-tail_budget:] if tail_budget else ""
    return {
        "head": head,
        "tail": tail,
        "truncated": True,
        "omitted_bytes": byte_len(text) - byte_len(head) - byte_len(tail),
        "omitted_chars": len(text) - len(head) - len(tail),
        "original_bytes": byte_len(text),
        "original_chars": len(text),
        "retained_bytes": byte_len(head) + byte_len(tail),
        "retained_chars": len(head) + len(tail),
    }
