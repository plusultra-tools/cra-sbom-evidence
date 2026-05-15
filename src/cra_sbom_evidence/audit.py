"""SHA-256 audit chain.

Produces a tamper-evident ``audit.sha256`` file that records the digests of
all input and output files, plus a chained hash that ties them together.

Pattern mirrors the dcm-anon audit chain: each entry is a hex digest +
filename on its own line; the chain appends a ``CHAIN`` digest that hashes
the concatenation of all previous digests.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Sequence


AUDIT_FILENAME = "audit.sha256"


def sha256_file(path: str | Path) -> str:
    """Compute the SHA-256 digest of a file's content.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex digest string (64 chars).

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found for hashing: {p}")
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    """Compute the SHA-256 digest of a UTF-8 string.

    Args:
        text: The string to hash.

    Returns:
        Lowercase hex digest string.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_audit_chain(
    input_paths: Sequence[str | Path],
    output_paths: Sequence[str | Path],
) -> str:
    """Build the audit chain text content.

    The format is:
    - One line per file: ``<sha256>  <label>``
    - Final line: ``CHAIN  <sha256-of-all-previous-digests-concatenated>``

    Args:
        input_paths: Paths to input files (SBOMs, VEX, product manifest).
        output_paths: Paths to output files (evidence JSON, Markdown).

    Returns:
        The full audit chain text, ready to write to ``audit.sha256``.
    """
    lines: list[str] = []
    digests: list[str] = []

    for p in input_paths:
        digest = sha256_file(p)
        label = f"INPUT:{Path(p).name}"
        lines.append(f"{digest}  {label}")
        digests.append(digest)

    for p in output_paths:
        digest = sha256_file(p)
        label = f"OUTPUT:{Path(p).name}"
        lines.append(f"{digest}  {label}")
        digests.append(digest)

    # Chain hash: SHA-256 of all digests concatenated
    chain_input = "".join(digests)
    chain_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
    lines.append(f"{chain_hash}  CHAIN")

    return "\n".join(lines) + "\n"


def write_audit_chain(
    output_dir: str | Path,
    input_paths: Sequence[str | Path],
    output_paths: Sequence[str | Path],
) -> str:
    """Write the audit chain to ``<output_dir>/audit.sha256``.

    Args:
        output_dir: Directory where ``audit.sha256`` will be written.
        input_paths: Input file paths.
        output_paths: Output file paths (must already exist).

    Returns:
        The SHA-256 digest of the ``audit.sha256`` file itself.
    """
    chain_text = build_audit_chain(input_paths, output_paths)
    audit_path = Path(output_dir) / AUDIT_FILENAME
    audit_path.write_text(chain_text, encoding="utf-8")
    return sha256_text(chain_text)


def verify_audit_chain(audit_path: str | Path) -> dict[str, Any]:
    """Verify a previously written audit chain.

    Reads ``audit.sha256``, recomputes all file digests, and checks the
    chain hash. Returns a report dict.

    Args:
        audit_path: Path to the ``audit.sha256`` file.

    Returns:
        A dict with keys ``ok`` (bool), ``entries`` (list), and ``chain_ok`` (bool).
    """
    p = Path(audit_path)
    if not p.exists():
        return {"ok": False, "error": f"Audit file not found: {p}", "entries": [], "chain_ok": False}

    parent = p.parent
    content = p.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]

    chain_line: str | None = None
    file_lines: list[str] = []
    for ln in lines:
        parts = ln.split("  ", 1)
        if len(parts) == 2 and parts[1].strip() == "CHAIN":
            chain_line = ln
        else:
            file_lines.append(ln)

    entries: list[dict[str, Any]] = []
    all_ok = True
    digests: list[str] = []

    for ln in file_lines:
        parts = ln.split("  ", 1)
        if len(parts) != 2:
            continue
        stored_hash, label = parts[0].strip(), parts[1].strip()
        # Resolve filename from label.
        # INPUT files are external and may not live in the pack directory;
        # we verify them only if they happen to be co-located.
        # OUTPUT files (prefix OUTPUT:) are always in the pack directory.
        prefix = label.split(":", 1)[0] if ":" in label else ""
        filename = label.split(":", 1)[-1] if ":" in label else label
        file_path = parent / filename

        if not file_path.exists():
            if prefix == "INPUT":
                # External input — skip verification, record as skipped
                entries.append({"label": label, "ok": True, "reason": "external input skipped"})
                digests.append(stored_hash)
                continue
            else:
                entries.append({"label": label, "ok": False, "reason": "file not found"})
                all_ok = False
                digests.append(stored_hash)
                continue

        actual_hash = sha256_file(file_path)
        ok = actual_hash == stored_hash
        if not ok:
            all_ok = False
        entries.append({"label": label, "stored": stored_hash, "actual": actual_hash, "ok": ok})
        digests.append(stored_hash)

    # Verify chain hash
    chain_ok = False
    if chain_line and digests:
        chain_stored = chain_line.split("  ", 1)[0].strip()
        chain_expected = hashlib.sha256("".join(digests).encode("utf-8")).hexdigest()
        chain_ok = chain_stored == chain_expected

    return {"ok": all_ok and chain_ok, "entries": entries, "chain_ok": chain_ok}
