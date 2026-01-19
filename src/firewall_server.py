#!/usr/bin/env python3
"""
Code Firewall MCP Server - Structural similarity-based code security filter.

Blocks dangerous code patterns before they reach execution tools like rlm_exec.
Uses tree-sitter for CST parsing, structural normalization, and Ollama embeddings
with ChromaDB for similarity matching against a blacklist of known-bad patterns.

Architecture:
1. Code comes in (file path)
2. Parse to CST via tree-sitter
3. Normalize: strip identifiers, literals → structural skeleton
4. Embed via Ollama
5. Check similarity against blacklist in ChromaDB
6. BLOCK if too similar to known-bad, ALLOW otherwise
7. Audit findings feed back into blacklist
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

# Conditional imports with availability flags
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False


# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = Path(os.environ.get("FIREWALL_DATA_DIR", "/tmp/code-firewall"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")

# Similarity threshold: 0.0-1.0, higher = more similar
# Patterns with similarity >= threshold to a blacklisted pattern are BLOCKED
SIMILARITY_THRESHOLD = float(os.environ.get("SIMILARITY_THRESHOLD", "0.85"))

# Near-miss threshold: patterns between this and SIMILARITY_THRESHOLD get recorded as deltas
NEAR_MISS_THRESHOLD = float(os.environ.get("NEAR_MISS_THRESHOLD", "0.70"))

# Initialize FastMCP server
mcp = FastMCP("code-firewall-mcp")

# ChromaDB client (lazy init)
_chroma_client: Optional[Any] = None
_blacklist_collection: Optional[Any] = None
_delta_collection: Optional[Any] = None

# Tree-sitter parser cache
_parsers: dict[str, Any] = {}


# =============================================================================
# ChromaDB Setup
# =============================================================================

def _get_chroma_client():
    """Get or create ChromaDB client."""
    global _chroma_client
    if _chroma_client is None:
        if not HAS_CHROMADB:
            raise RuntimeError("chromadb not installed. Run: pip install chromadb")
        _chroma_client = chromadb.PersistentClient(
            path=str(DATA_DIR / "chromadb"),
            settings=Settings(anonymized_telemetry=False),
        )
    return _chroma_client


def _get_blacklist_collection():
    """Get or create the blacklist collection."""
    global _blacklist_collection
    if _blacklist_collection is None:
        client = _get_chroma_client()
        _blacklist_collection = client.get_or_create_collection(
            name="blacklist",
            metadata={"description": "Known dangerous code patterns"},
        )
    return _blacklist_collection


def _get_delta_collection():
    """Get or create the delta/near-miss collection."""
    global _delta_collection
    if _delta_collection is None:
        client = _get_chroma_client()
        _delta_collection = client.get_or_create_collection(
            name="deltas",
            metadata={"description": "Near-miss variants for classifier sharpening"},
        )
    return _delta_collection


# =============================================================================
# Tree-sitter Parsing
# =============================================================================

def _get_parser(language: str) -> Optional[Any]:
    """Get or create a tree-sitter parser for the given language."""
    if not HAS_TREE_SITTER:
        return None

    if language in _parsers:
        return _parsers[language]

    parser = Parser()

    if language == "python":
        parser.language = Language(tspython.language())
    else:
        # Add more languages as needed
        return None

    _parsers[language] = parser
    return parser


def _detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, "unknown")


def _parse_to_cst(code: str, language: str) -> Optional[Any]:
    """Parse code to CST using tree-sitter."""
    parser = _get_parser(language)
    if parser is None:
        return None

    tree = parser.parse(bytes(code, "utf-8"))
    return tree.root_node


# =============================================================================
# Structural Normalization
# =============================================================================

def _normalize_node(node, depth: int = 0) -> str:
    """
    Recursively normalize a CST node to its structural skeleton.

    - Strips identifier names → replaced with '_'
    - Strips literal values → replaced with type marker
    - Preserves node types and structure
    - Returns compact string representation
    """
    if node is None:
        return ""

    node_type = node.type

    # Replace identifiers with placeholder
    if node_type == "identifier":
        return "_"

    # Replace literals with type markers
    if node_type in ("string", "string_literal"):
        return '"S"'
    if node_type in ("integer", "number", "float"):
        return "N"
    if node_type in ("true", "false"):
        return "B"
    if node_type == "none":
        return "X"

    # For leaf nodes, just return the type
    if node.child_count == 0:
        return node_type

    # Recursively process children
    children_str = " ".join(
        _normalize_node(child, depth + 1)
        for child in node.children
        if child.type not in ("comment", "line_comment", "block_comment")
    )

    # Compact representation: (type children...)
    return f"({node_type} {children_str})"


def _normalize_code(code: str, language: str) -> Optional[str]:
    """
    Normalize code to structural skeleton.

    Returns a compact string representation of the code structure
    with all identifiers and literals stripped.
    """
    root = _parse_to_cst(code, language)
    if root is None:
        return None

    normalized = _normalize_node(root)

    # Compact whitespace
    normalized = re.sub(r'\s+', ' ', normalized)

    return normalized.strip()


def _normalize_code_fallback(code: str) -> str:
    """
    Fallback normalization when tree-sitter is unavailable.

    Uses regex-based normalization (less accurate but works without dependencies).
    """
    # Strip comments
    code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)  # Python comments
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)  # C-style line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Block comments

    # Replace string literals
    code = re.sub(r'"[^"]*"', '"S"', code)
    code = re.sub(r"'[^']*'", '"S"', code)

    # Replace numbers
    code = re.sub(r'\b\d+\.?\d*\b', 'N', code)

    # Replace identifiers (simple heuristic: word characters not keywords)
    keywords = {
        'import', 'from', 'def', 'class', 'return', 'if', 'else', 'elif',
        'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'async',
        'await', 'yield', 'raise', 'pass', 'break', 'continue', 'and', 'or',
        'not', 'in', 'is', 'lambda', 'global', 'nonlocal', 'True', 'False', 'None',
    }

    def replace_identifier(match):
        word = match.group(0)
        return word if word in keywords else '_'

    code = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', replace_identifier, code)

    # Compact whitespace
    code = re.sub(r'\s+', ' ', code)

    return code.strip()


def normalize_code(code: str, language: str = "python") -> str:
    """
    Normalize code to structural skeleton.

    Tries tree-sitter first, falls back to regex-based normalization.
    """
    if HAS_TREE_SITTER:
        result = _normalize_code(code, language)
        if result:
            return result

    return _normalize_code_fallback(code)


# =============================================================================
# Ollama Embeddings
# =============================================================================

async def _get_embedding(text: str) -> Optional[list[float]]:
    """Get embedding vector from Ollama."""
    if not HAS_HTTPX:
        return None

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/embed",
                json={
                    "model": EMBEDDING_MODEL,
                    "input": text,
                },
            )
            response.raise_for_status()
            data = response.json()

            # Handle both single and batch embedding responses
            embeddings = data.get("embeddings", [])
            if embeddings and len(embeddings) > 0:
                return embeddings[0]

            # Fallback for older API format
            return data.get("embedding", None)

    except Exception as e:
        print(f"Embedding error: {e}")
        return None


def _hash_structure(normalized: str) -> str:
    """Create a hash of the normalized structure for deduplication."""
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


# =============================================================================
# Firewall Logic
# =============================================================================

async def _check_against_blacklist(
    normalized: str,
    embedding: list[float],
) -> dict:
    """
    Check if code structure matches any blacklisted pattern.

    Returns:
        {
            "blocked": bool,
            "similarity": float,
            "matched_id": str | None,
            "matched_reason": str | None,
            "near_miss": bool,
        }
    """
    collection = _get_blacklist_collection()

    # Query for similar patterns
    results = collection.query(
        query_embeddings=[embedding],
        n_results=3,
        include=["metadatas", "distances"],
    )

    if not results["ids"] or not results["ids"][0]:
        return {
            "blocked": False,
            "similarity": 0.0,
            "matched_id": None,
            "matched_reason": None,
            "near_miss": False,
        }

    # ChromaDB returns L2 distance, convert to similarity (cosine-ish)
    # Lower distance = more similar
    distances = results["distances"][0]
    ids = results["ids"][0]
    metadatas = results["metadatas"][0]

    # Convert L2 distance to similarity score (approximate)
    # This is a rough approximation; for normalized vectors, similarity ≈ 1 - distance²/2
    best_distance = distances[0]
    similarity = max(0.0, 1.0 - (best_distance ** 2) / 2)

    matched_id = ids[0]
    matched_reason = metadatas[0].get("reason", "Unknown") if metadatas else "Unknown"

    blocked = similarity >= SIMILARITY_THRESHOLD
    near_miss = not blocked and similarity >= NEAR_MISS_THRESHOLD

    return {
        "blocked": blocked,
        "similarity": round(similarity, 4),
        "matched_id": matched_id if (blocked or near_miss) else None,
        "matched_reason": matched_reason if blocked else None,
        "near_miss": near_miss,
    }


# =============================================================================
# MCP Tools
# =============================================================================

@mcp.tool()
async def firewall_check(file_path: str) -> dict:
    """
    Check if code is safe to pass to execution tools like rlm_exec.

    Parses the code, normalizes to structural skeleton, embeds via Ollama,
    and checks similarity against blacklisted dangerous patterns.

    Args:
        file_path: Path to the code file to check

    Returns:
        {
            "allowed": bool,          # True if safe to proceed
            "blocked": bool,          # True if matched blacklist
            "similarity": float,      # Similarity to closest blacklist match (0-1)
            "matched_pattern": str,   # ID of matched pattern (if blocked)
            "reason": str,            # Why it was blocked (if blocked)
            "near_miss": bool,        # True if close but not blocked
            "structure_hash": str,    # Hash of normalized structure
        }
    """
    path = Path(file_path)

    if not path.exists():
        return {"error": "file_not_found", "message": f"File not found: {file_path}"}

    if not path.is_file():
        return {"error": "not_a_file", "message": f"Not a file: {file_path}"}

    # Read and normalize code
    try:
        code = path.read_text()
    except Exception as e:
        return {"error": "read_error", "message": str(e)}

    language = _detect_language(file_path)
    normalized = normalize_code(code, language)
    structure_hash = _hash_structure(normalized)

    # Get embedding
    embedding = await _get_embedding(normalized)
    if embedding is None:
        return {
            "error": "embedding_failed",
            "message": "Could not generate embedding. Is Ollama running?",
            "structure_hash": structure_hash,
        }

    # Check against blacklist
    result = await _check_against_blacklist(normalized, embedding)

    return {
        "allowed": not result["blocked"],
        "blocked": result["blocked"],
        "similarity": result["similarity"],
        "matched_pattern": result["matched_id"],
        "reason": result["matched_reason"],
        "near_miss": result["near_miss"],
        "structure_hash": structure_hash,
        "language": language,
        "normalized_length": len(normalized),
    }


@mcp.tool()
async def firewall_check_code(code: str, language: str = "python") -> dict:
    """
    Check if code string is safe (without requiring a file).

    Args:
        code: The code to check
        language: Programming language (default: python)

    Returns:
        Same as firewall_check
    """
    normalized = normalize_code(code, language)
    structure_hash = _hash_structure(normalized)

    embedding = await _get_embedding(normalized)
    if embedding is None:
        return {
            "error": "embedding_failed",
            "message": "Could not generate embedding. Is Ollama running?",
            "structure_hash": structure_hash,
        }

    result = await _check_against_blacklist(normalized, embedding)

    return {
        "allowed": not result["blocked"],
        "blocked": result["blocked"],
        "similarity": result["similarity"],
        "matched_pattern": result["matched_id"],
        "reason": result["matched_reason"],
        "near_miss": result["near_miss"],
        "structure_hash": structure_hash,
        "language": language,
        "normalized_length": len(normalized),
    }


@mcp.tool()
async def firewall_blacklist(
    file_path: Optional[str] = None,
    code: Optional[str] = None,
    reason: str = "Security risk",
    severity: str = "high",
    language: str = "python",
) -> dict:
    """
    Add a code pattern to the blacklist.

    Either file_path or code must be provided.

    Args:
        file_path: Path to code file to blacklist
        code: Code string to blacklist (alternative to file_path)
        reason: Why this pattern is dangerous
        severity: critical, high, medium, low
        language: Programming language (used if code is provided)

    Returns:
        {"status": "added", "pattern_id": str, "structure_hash": str}
    """
    if file_path:
        path = Path(file_path)
        if not path.exists():
            return {"error": "file_not_found", "message": f"File not found: {file_path}"}
        code = path.read_text()
        language = _detect_language(file_path)
    elif code:
        pass  # Use provided code and language
    else:
        return {"error": "no_input", "message": "Provide either file_path or code"}

    normalized = normalize_code(code, language)
    structure_hash = _hash_structure(normalized)

    embedding = await _get_embedding(normalized)
    if embedding is None:
        return {"error": "embedding_failed", "message": "Could not generate embedding"}

    collection = _get_blacklist_collection()

    # Check if already exists
    existing = collection.get(ids=[structure_hash])
    if existing["ids"]:
        return {
            "status": "already_exists",
            "pattern_id": structure_hash,
            "message": "Pattern already in blacklist",
        }

    # Add to blacklist
    collection.add(
        ids=[structure_hash],
        embeddings=[embedding],
        metadatas=[{
            "reason": reason,
            "severity": severity,
            "language": language,
            "normalized_preview": normalized[:200],
        }],
        documents=[normalized],
    )

    return {
        "status": "added",
        "pattern_id": structure_hash,
        "structure_hash": structure_hash,
        "normalized_length": len(normalized),
    }


@mcp.tool()
async def firewall_record_delta(
    file_path: Optional[str] = None,
    code: Optional[str] = None,
    similar_to: str = "",
    notes: str = "",
    language: str = "python",
) -> dict:
    """
    Record a near-miss variant to help sharpen the classifier.

    Use this when code is similar to a blacklisted pattern but represents
    a legitimate use case, or when a new variant of a dangerous pattern
    is discovered.

    Args:
        file_path: Path to code file
        code: Code string (alternative to file_path)
        similar_to: Pattern ID this is similar to
        notes: Notes about why this is being recorded
        language: Programming language

    Returns:
        {"status": "recorded", "delta_id": str}
    """
    if file_path:
        path = Path(file_path)
        if not path.exists():
            return {"error": "file_not_found", "message": f"File not found: {file_path}"}
        code = path.read_text()
        language = _detect_language(file_path)
    elif code:
        pass
    else:
        return {"error": "no_input", "message": "Provide either file_path or code"}

    normalized = normalize_code(code, language)
    structure_hash = _hash_structure(normalized)

    embedding = await _get_embedding(normalized)
    if embedding is None:
        return {"error": "embedding_failed", "message": "Could not generate embedding"}

    collection = _get_delta_collection()

    # Add to deltas
    delta_id = f"delta_{structure_hash}"
    collection.add(
        ids=[delta_id],
        embeddings=[embedding],
        metadatas=[{
            "similar_to": similar_to,
            "notes": notes,
            "language": language,
            "structure_hash": structure_hash,
        }],
        documents=[normalized],
    )

    return {
        "status": "recorded",
        "delta_id": delta_id,
        "structure_hash": structure_hash,
        "similar_to": similar_to,
    }


@mcp.tool()
async def firewall_list_patterns(
    collection_name: str = "blacklist",
    limit: int = 50,
) -> dict:
    """
    List patterns in the blacklist or delta collection.

    Args:
        collection_name: "blacklist" or "deltas"
        limit: Maximum number of patterns to return

    Returns:
        {"patterns": [...], "count": int}
    """
    if collection_name == "blacklist":
        collection = _get_blacklist_collection()
    elif collection_name == "deltas":
        collection = _get_delta_collection()
    else:
        return {"error": "invalid_collection", "message": "Use 'blacklist' or 'deltas'"}

    results = collection.get(
        limit=limit,
        include=["metadatas"],
    )

    patterns = []
    for i, id_ in enumerate(results["ids"]):
        meta = results["metadatas"][i] if results["metadatas"] else {}
        patterns.append({
            "id": id_,
            "reason": meta.get("reason", ""),
            "severity": meta.get("severity", ""),
            "language": meta.get("language", ""),
            "preview": meta.get("normalized_preview", "")[:100],
        })

    return {
        "collection": collection_name,
        "patterns": patterns,
        "count": len(patterns),
    }


@mcp.tool()
async def firewall_remove_pattern(pattern_id: str, collection_name: str = "blacklist") -> dict:
    """
    Remove a pattern from the blacklist or delta collection.

    Args:
        pattern_id: The pattern ID to remove
        collection_name: "blacklist" or "deltas"

    Returns:
        {"status": "removed", "pattern_id": str}
    """
    if collection_name == "blacklist":
        collection = _get_blacklist_collection()
    elif collection_name == "deltas":
        collection = _get_delta_collection()
    else:
        return {"error": "invalid_collection", "message": "Use 'blacklist' or 'deltas'"}

    # Check if exists
    existing = collection.get(ids=[pattern_id])
    if not existing["ids"]:
        return {"error": "not_found", "message": f"Pattern not found: {pattern_id}"}

    collection.delete(ids=[pattern_id])

    return {
        "status": "removed",
        "pattern_id": pattern_id,
        "collection": collection_name,
    }


@mcp.tool()
async def firewall_status() -> dict:
    """
    Get firewall status and statistics.

    Returns:
        {
            "ollama_available": bool,
            "chromadb_available": bool,
            "tree_sitter_available": bool,
            "blacklist_count": int,
            "delta_count": int,
            "similarity_threshold": float,
            "near_miss_threshold": float,
        }
    """
    blacklist_count = 0
    delta_count = 0

    try:
        if HAS_CHROMADB:
            blacklist_count = _get_blacklist_collection().count()
            delta_count = _get_delta_collection().count()
    except Exception:
        pass

    # Check Ollama
    ollama_available = False
    if HAS_HTTPX:
        try:
            import asyncio
            async def check():
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(f"{OLLAMA_URL}/api/tags")
                    return response.status_code == 200
            ollama_available = asyncio.get_event_loop().run_until_complete(check())
        except Exception:
            pass

    return {
        "ollama_available": ollama_available,
        "ollama_url": OLLAMA_URL,
        "embedding_model": EMBEDDING_MODEL,
        "chromadb_available": HAS_CHROMADB,
        "tree_sitter_available": HAS_TREE_SITTER,
        "blacklist_count": blacklist_count,
        "delta_count": delta_count,
        "similarity_threshold": SIMILARITY_THRESHOLD,
        "near_miss_threshold": NEAR_MISS_THRESHOLD,
        "data_dir": str(DATA_DIR),
    }


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
