# Code Firewall MCP

<!-- mcp-name: io.github.egoughnour/code-firewall-mcp -->

A structural similarity-based code security filter for MCP (Model Context Protocol). Blocks dangerous code patterns before they reach execution tools by comparing code structure against a blacklist of known-bad patterns.

## How It Works

```
┌──────────┐    ┌─────────────┐    ┌───────────────────┐    ┌─────────────────────┐
│ Code     │───▶│ CST → Embed │───▶│ Similarity Check  │───▶│ Execution Tools     │
│ (file)   │    │ (tree-sitter│    │ vs blacklist      │    │ (rlm_exec, etc.)    │
└──────────┘    │  + Ollama)  │    │ (ChromaDB)        │    └─────────────────────┘
                └─────────────┘    └─────────┬─────────┘
                                             │
                                    ┌────────┴────────┐
                                    ▼                 ▼
                               [BLOCKED]         [ALLOWED]
```

1. **Parse** code to Concrete Syntax Tree (CST) using tree-sitter
2. **Normalize** by stripping identifiers and literals → structural skeleton
3. **Embed** the normalized structure via Ollama
4. **Compare** against blacklisted patterns in ChromaDB
5. **Block** if similarity exceeds threshold, otherwise **allow**

## Key Insight

Code patterns like `os.system("rm -rf /")` and `os.system("ls")` have **identical structure**. By normalizing away the specific commands/identifiers, we can detect dangerous patterns regardless of the specific arguments used.

## Installation

```bash
# Via uvx (recommended)
uvx code-firewall-mcp

# Or install from source
pip install -e .
```

## Requirements

- Python 3.10+
- Ollama (for embeddings)
- ChromaDB (for vector storage)
- tree-sitter (optional, for better parsing)

Pull an embedding model:
```bash
ollama pull nomic-embed-text
```

## Tools

### `firewall_check`
Check if a code file is safe to pass to execution tools.

```python
result = await firewall_check(file_path="/path/to/script.py")
# Returns: {allowed: bool, blocked: bool, similarity: float, ...}
```

### `firewall_check_code`
Check code string directly (no file required).

```python
result = await firewall_check_code(
    code="import os; os.system('rm -rf /')",
    language="python"
)
```

### `firewall_blacklist`
Add a dangerous pattern to the blacklist.

```python
result = await firewall_blacklist(
    code="os.system(arbitrary_command)",
    reason="Arbitrary command execution",
    severity="critical"
)
```

### `firewall_record_delta`
Record near-miss variants to sharpen the classifier.

```python
result = await firewall_record_delta(
    code="subprocess.run(['ls', '-la'])",
    similar_to="abc123",
    notes="Legitimate use case for file listing"
)
```

### `firewall_list_patterns`
List patterns in the blacklist or delta collection.

### `firewall_remove_pattern`
Remove a pattern from blacklist or deltas.

### `firewall_status`
Get firewall status and statistics.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `FIREWALL_DATA_DIR` | `/tmp/code-firewall` | Data storage directory |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Ollama embedding model |
| `SIMILARITY_THRESHOLD` | `0.85` | Block threshold (0-1) |
| `NEAR_MISS_THRESHOLD` | `0.70` | Near-miss recording threshold |

## Usage Pattern

### Pre-filter for massive-context-mcp

Use code-firewall-mcp as a gatekeeper before passing code to `rlm_exec`:

```python
# 1. Check code safety
check = await firewall_check_code(user_code)

if check["blocked"]:
    print(f"BLOCKED: {check['reason']}")
    return

# 2. If allowed, proceed with execution
result = await rlm_exec(code=user_code, context_name="my-context")
```

### Building the Blacklist

The blacklist grows through use:

1. **Initial seeding**: Add known dangerous patterns
2. **Audit feedback**: When `rlm_auto_analyze` finds security issues, add patterns
3. **Delta sharpening**: Record near-misses to improve classification boundaries

```python
# After security audit finds issues
await firewall_blacklist(
    code=dangerous_code,
    reason="Command injection via subprocess",
    severity="critical"
)
```

## Structural Normalization

The normalizer strips:
- **Identifiers**: `my_var` → `_`
- **String literals**: `"hello"` → `"S"`
- **Numbers**: `42` → `N`
- **Comments**: Removed entirely

Example:
```python
# Original
subprocess.run(["curl", url, "-o", output_file])

# Normalized
_._(["S", _, "S", _])
```

Both `subprocess.run(["curl", ...])` and `subprocess.run(["wget", ...])` normalize to the same structure, so blacklisting one catches both.

## License

MIT
