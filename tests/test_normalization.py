"""Tests for code normalization."""

import pytest
from src.firewall_server import (
    normalize_code,
    _normalize_code_fallback,
    _hash_structure,
    SECURITY_SENSITIVE_IDENTIFIERS,
)


class TestNormalizationFallback:
    """Test regex-based fallback normalization."""

    def test_strips_string_literals(self):
        code = 'x = "hello world"'
        result = _normalize_code_fallback(code)
        assert '"hello world"' not in result
        assert '"S"' in result

    def test_strips_single_quoted_strings(self):
        code = "x = 'hello world'"
        result = _normalize_code_fallback(code)
        assert "'hello world'" not in result
        assert '"S"' in result

    def test_strips_numbers(self):
        code = "x = 42 + 3.14"
        result = _normalize_code_fallback(code)
        assert "42" not in result
        assert "3.14" not in result
        assert "N" in result

    def test_strips_identifiers(self):
        code = "my_variable = another_var"
        result = _normalize_code_fallback(code)
        assert "my_variable" not in result
        assert "another_var" not in result
        assert "_" in result

    def test_preserves_keywords(self):
        code = "if True: return None"
        result = _normalize_code_fallback(code)
        assert "if" in result
        assert "return" in result
        assert "None" in result

    def test_strips_comments(self):
        code = "x = 1  # this is a comment"
        result = _normalize_code_fallback(code)
        assert "comment" not in result

    def test_compacts_whitespace(self):
        code = "x   =    1\n\n\ny = 2"
        result = _normalize_code_fallback(code)
        assert "   " not in result


class TestSecuritySensitiveIdentifiers:
    """Test that security-sensitive identifiers are preserved."""

    def test_preserves_eval(self):
        code = "eval(user_input)"
        result = _normalize_code_fallback(code)
        assert "eval" in result
        assert "user_input" not in result

    def test_preserves_exec(self):
        code = "exec(code_string)"
        result = _normalize_code_fallback(code)
        assert "exec" in result
        assert "code_string" not in result

    def test_preserves_os_system(self):
        code = 'os.system("rm -rf /")'
        result = _normalize_code_fallback(code)
        assert "os" in result
        assert "system" in result

    def test_preserves_subprocess(self):
        code = "subprocess.Popen(['ls'], shell=True)"
        result = _normalize_code_fallback(code)
        assert "subprocess" in result
        assert "Popen" in result
        assert "shell" in result

    def test_preserves_dangerous_builtins(self):
        code = "__import__('os').system('cmd')"
        result = _normalize_code_fallback(code)
        assert "__import__" in result
        assert "system" in result
        # Note: 'os' is inside a string literal, so it becomes "S"
        # That's correct - we preserve the identifier __import__ and system,
        # but string contents are still normalized

    def test_preserves_reflection(self):
        code = "getattr(obj, attr_name)"
        result = _normalize_code_fallback(code)
        assert "getattr" in result
        assert "obj" not in result
        assert "attr_name" not in result

    def test_preserves_file_operations(self):
        code = "open(filename).read()"
        result = _normalize_code_fallback(code)
        assert "open" in result
        assert "read" in result
        assert "filename" not in result

    def test_security_identifiers_set_not_empty(self):
        """Ensure the security identifiers set contains expected items."""
        assert "eval" in SECURITY_SENSITIVE_IDENTIFIERS
        assert "exec" in SECURITY_SENSITIVE_IDENTIFIERS
        assert "system" in SECURITY_SENSITIVE_IDENTIFIERS
        assert "subprocess" in SECURITY_SENSITIVE_IDENTIFIERS
        assert "Popen" in SECURITY_SENSITIVE_IDENTIFIERS
        assert "shell" in SECURITY_SENSITIVE_IDENTIFIERS


class TestStructuralEquivalence:
    """Test that structurally similar code normalizes to the same form."""

    def test_os_system_variants_normalize_same(self):
        code1 = 'os.system("rm -rf /")'
        code2 = 'os.system("ls -la")'
        code3 = 'os.system(user_input)'

        norm1 = _normalize_code_fallback(code1)
        norm2 = _normalize_code_fallback(code2)
        norm3 = _normalize_code_fallback(code3)

        # Both with string literals should be the same
        assert norm1 == norm2
        # With identifier differs (identifier becomes _)
        assert norm1 != norm3
        # But all preserve os.system
        assert "os.system" in norm1
        assert "os.system" in norm3

    def test_function_calls_same_structure(self):
        code1 = "subprocess.run(['curl', url])"
        code2 = "subprocess.run(['wget', target])"

        norm1 = _normalize_code_fallback(code1)
        norm2 = _normalize_code_fallback(code2)

        # Should be equivalent structures (subprocess.run preserved)
        assert norm1 == norm2
        assert "subprocess" in norm1
        assert "run" in norm1

    def test_different_structures_normalize_differently(self):
        code1 = "os.system(cmd)"
        code2 = "print(msg)"

        norm1 = _normalize_code_fallback(code1)
        norm2 = _normalize_code_fallback(code2)

        # Now these are DIFFERENT because os.system is preserved
        assert norm1 != norm2
        assert "os" in norm1
        assert "system" in norm1
        assert "os" not in norm2


class TestHashStructure:
    """Test structural hashing."""

    def test_same_structure_same_hash(self):
        norm1 = "_._(S)"
        norm2 = "_._(S)"
        assert _hash_structure(norm1) == _hash_structure(norm2)

    def test_different_structure_different_hash(self):
        norm1 = "_._(S)"
        norm2 = "_._(S, S)"
        assert _hash_structure(norm1) != _hash_structure(norm2)

    def test_hash_is_stable(self):
        normalized = "def _(_): return _"
        hash1 = _hash_structure(normalized)
        hash2 = _hash_structure(normalized)
        assert hash1 == hash2

    def test_hash_length(self):
        normalized = "some normalized code"
        result = _hash_structure(normalized)
        assert len(result) == 16  # SHA256 truncated to 16 chars


class TestNormalizeCode:
    """Test the main normalize_code function."""

    def test_falls_back_gracefully(self):
        # Even without tree-sitter, should work via fallback
        code = "x = 1 + 2"
        result = normalize_code(code, "python")
        assert result is not None
        assert len(result) > 0

    def test_handles_empty_code(self):
        result = normalize_code("", "python")
        assert result == ""

    def test_handles_whitespace_only(self):
        result = normalize_code("   \n\n   ", "python")
        assert result == ""
