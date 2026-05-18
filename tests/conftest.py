"""
Shared pytest fixtures for shai_hulud_guard tests.

Both v1.1 (shai_hulud_guard.py) and v2.0 (shai_hulud_guard V2.0.py) are
loaded via importlib because:
  - V2.0's filename contains a space (cannot be imported with `import`)
  - We want to test both without renaming user-facing files

All synthetic tarballs are constructed in memory. We never check a real
malicious tarball into the repo. Strings that *look* like IOCs (e.g. the
literal "Shai-Hulud") are deliberate and only appear inside fixtures.
"""
from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
V1_PATH = REPO_ROOT / "shai_hulud_guard.py"
V2_PATH = REPO_ROOT / "shai_hulud_guard V2.0.py"


def _load(module_name: str, path: Path) -> ModuleType:
    if not path.exists():
        pytest.skip(f"{path.name} not present in repo root")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def v1():
    """The v1.1.0 module."""
    return _load("shg_v1", V1_PATH)


@pytest.fixture(scope="session")
def v2():
    """The v2.0.0 module."""
    return _load("shg_v2", V2_PATH)


# ─────────────────────────────────────────────────────────────────────────────
#  Tarball builders — every test that needs a tarball builds one in memory.
#  We never read or write tarballs from / to disk in tests.
# ─────────────────────────────────────────────────────────────────────────────

def _make_tarball(members: dict[str, bytes]) -> bytes:
    """Build a gzipped tar archive from {member_name: content_bytes}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def make_tarball():
    """Factory: hand it {filename: bytes} and get back gzipped tar bytes."""
    return _make_tarball


@pytest.fixture
def clean_tarball(make_tarball):
    """A tarball with a single, benign README and a plausible package.json."""
    return make_tarball({
        "package/README.md":     b"# my-lib\nNo malicious content here.\n",
        "package/package.json":  b'{"name":"my-lib","version":"1.0.0"}',
        "package/lib/index.js":  b"module.exports = function add(a, b) { return a + b; };\n",
    })


@pytest.fixture
def payload_filename_tarball(make_tarball):
    """A tarball containing one of the worm's known payload filenames."""
    return make_tarball({
        "package/package.json":  b'{"name":"evil","version":"1.0.0"}',
        "package/router_init.js": b"// (benign content in fixture)\nconsole.log('hello');\n",
    })


@pytest.fixture
def worm_string_tarball(make_tarball):
    """A tarball whose JS file contains the worm identity string."""
    return make_tarball({
        "package/package.json": b'{"name":"evil","version":"1.0.0"}',
        # Deliberately the literal worm marker; only inside this fixture.
        "package/lib/index.js": b"// Shai-Hulud was here\nconsole.log('x');\n",
    })


@pytest.fixture
def lodash_like_unicode_tarball(make_tarball):
    """
    A tarball mimicking what a real i18n library (e.g. lodash, core-js) ships:
    long runs of high-codepoint \\u escapes. The scanner's unicode-escape
    pattern is deliberately scoped to the ASCII range (\\u0020–\\u007F) to
    AVOID matching this — see CLAUDE.md §5.6. This fixture exists to
    regression-guard that exclusion.
    """
    # Construct the JS source as a Python string, then encode. The intent is
    # for the *contents of the JS file* to literally contain "Ơơ..."
    # — sequences of backslash-u-XXXX where XX >= 80. That requires us to
    # write the escape sequences as ASCII bytes, not actual unicode codepoints.
    js_lines = ["// i18n character tables — high-codepoint unicode escapes\n"]
    for _ in range(40):
        # 8 high-range escapes per line — well above the 4-in-a-row threshold
        js_lines.append("var x = '\\u01A0\\u01A1\\u01B2\\u01C3\\u01D4\\u01E5\\u01F6\\u02A7';\n")
    return make_tarball({
        "package/package.json": b'{"name":"i18n-lib","version":"1.0.0"}',
        "package/lib/chars.js": "".join(js_lines).encode("utf-8"),
    })


@pytest.fixture
def ascii_obfuscated_tarball(make_tarball):
    """
    A tarball whose JS file contains ASCII-range unicode escapes — what the
    worm uses to hide identifiers. The scanner's pattern SHOULD match this.
    """
    # eval  encodes "eval" — actual worm obfuscation style.
    js = (
        b"// payload\n"
        b"var x = '\\u0065\\u0076\\u0061\\u006C\\u0028\\u0061\\u0074\\u006F\\u0062';\n"
    )
    return make_tarball({
        "package/package.json": b'{"name":"obf","version":"1.0.0"}',
        "package/lib/payload.js": js,
    })


@pytest.fixture
def binary_garbage_tarball(make_tarball):
    """A tarball with a non-text member with .js suffix containing binary garbage."""
    return make_tarball({
        "package/package.json": b'{"name":"binary","version":"1.0.0"}',
        # Random-looking bytes, including ones that don't decode as UTF-8.
        "package/lib/blob.js":  bytes(range(256)) * 4,
    })
