"""Tests for tools/go.meta.gen.py: the go/ast front end against the regex reader.

The tests that need a Go toolchain skip when there is none, unless
GO_META_REQUIRE_GO=1 (set in CI) — then a missing toolchain is a failure, so the
go/ast path cannot go unverified without anyone noticing.
"""
import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[2] / "tools"
_SAMPLE = _TOOLS / "goastdump" / "testdata" / "sample.go"

_spec = importlib.util.spec_from_file_location("go_meta_gen", _TOOLS / "go.meta.gen.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

HAVE_GO = shutil.which("go") is not None or bool(os.environ.get("GO_META_GOASTDUMP"))


def needs_go(fn):
    if os.environ.get("GO_META_REQUIRE_GO") == "1":
        return fn  # no skip: a missing toolchain must fail the run

    return pytest.mark.skipif(not HAVE_GO, reason="no Go toolchain")(fn)


def _names(data):
    return {(o["kind"], o["name"]) for o in data["objects"]}


EXPECTED = {
    ("const", "Alpha"), ("const", "Beta"), ("const", "Solo"), ("var", "Gamma"),
    ("interface", "Store"), ("struct", "Box"), ("type", "Alias"), ("type", "Number"),
    ("struct", "NoopSink"), ("method", "RecordTrace"), ("method", "Put"),
    ("func", "Handle"), ("func", "Shadow"), ("func", "Generic"), ("func", "Identity"),
}


# --- no Go needed: the dump -> objects translation -------------------------

def _dump(objects, imports=None):
    return {"file": "x.go", "package": "p", "package_doc": "", "imports": imports or {},
            "objects": objects}


def _obj(kind, name, **kw):
    base = {"name": name, "kind": kind, "doc": "", "refs": [], "calls": []}
    base.update(kw)
    return base


def test_objects_from_dump_filters_stdlib_and_formats_calls():
    imports = {"fmt": "fmt", "cab": "example.com/x/cabinet"}
    fn = _obj("func", "Run",
              refs=[{"pkg": "fmt", "name": "Println"}, {"pkg": "cab", "name": "Cabinet"}],
              calls=[{"pkg": "fmt", "name": "Println"},
                     {"pkg": "cab", "type": "Cabinet", "name": "Set"},
                     {"type": "Local", "name": "Do"},
                     {"name": "Bare"}])
    (obj,) = gen._objects_from_dump(_dump([fn], imports), imports)
    assert obj["references"] == ["cab.Cabinet", "cab.Cabinet.Set"]
    assert obj["calls"] == ["Bare", "Local.Do", "cab.Cabinet.Set"]


def test_objects_from_dump_keeps_regex_grouping_and_key_order():
    objs = [_obj("const", "C"), _obj("func", "F"), _obj("struct", "S"),
            _obj("interface", "I", methods=["M"]), _obj("type", "T"), _obj("var", "V")]
    out = gen._objects_from_dump(_dump(objs), {})
    assert [o["kind"] for o in out] == ["struct", "interface", "type", "func", "var", "const"]
    assert list(out[0]) == ["name", "kind", "description", "implements", "references"]
    assert out[1]["methods"] == ["M"]


# --- Go needed: the real front end -----------------------------------------

@needs_go
def test_ast_mode_finds_every_declaration():
    dumps = gen._ast_dump([_SAMPLE])
    data = gen.generate(_SAMPLE, dumps[_SAMPLE.resolve()])
    assert _names(data) == EXPECTED


@needs_go
def test_regex_mode_misses_what_ast_finds():
    """Pins the gap the migration closes; if the regex reader ever catches up,
    this fails and the comparison above needs a fresh look."""
    missed = EXPECTED - _names(gen.generate(_SAMPLE))
    assert ("const", "Beta") in missed          # grouped const block
    assert ("method", "RecordTrace") in missed  # unnamed receiver
    assert ("func", "Shadow") in missed or ("func", "Generic") in missed  # after a '//' string


@needs_go
def test_ast_references_and_calls_on_sample():
    dumps = gen._ast_dump([_SAMPLE])
    data = gen.generate(_SAMPLE, dumps[_SAMPLE.resolve()])
    handle = next(o for o in data["objects"] if o["name"] == "Handle")
    assert "cab.Cabinet.Set" in handle["references"]   # call typed through the parameter
    assert "yaml.Unmarshal" in handle["references"]    # gopkg.in/yaml.v3 -> alias yaml
    assert "lib.Run" in handle["references"]           # .../lib/v2 -> alias lib
    assert not any(r.startswith("fmt.") for r in handle["references"])  # stdlib dropped
    shadow = next(o for o in data["objects"] if o["name"] == "Shadow")
    assert shadow["references"] == []                  # local var hides the import


# --- fallback behaviour ----------------------------------------------------

def _run_main(monkeypatch, tmp_path, *argv):
    monkeypatch.setattr(gen, "_ast_bin", None)
    monkeypatch.setattr(gen.shutil, "which", lambda _: None)
    monkeypatch.delenv("GO_META_GOASTDUMP", raising=False)
    src = tmp_path / "a.go"
    src.write_text("package a\n\nfunc F() {}\n")
    monkeypatch.setattr(sys, "argv", ["go.meta.gen.py", *argv, str(src)])
    return src


def test_ast_mode_without_go_is_an_error(monkeypatch, tmp_path, capsys):
    src = _run_main(monkeypatch, tmp_path, "--parser", "ast")
    with pytest.raises(SystemExit) as e:
        gen.main()
    assert e.value.code == 2
    assert not src.with_suffix(".yaml").exists()


def test_auto_mode_without_go_warns_and_falls_back(monkeypatch, tmp_path, capsys):
    src = _run_main(monkeypatch, tmp_path)
    gen.main()
    assert "falling back to the regex reader" in capsys.readouterr().err
    assert src.with_suffix(".yaml").exists()
