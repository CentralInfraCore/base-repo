"""verify_release — single-command, offline release-readiness check.

Runs five checks against the working tree and prints a PASS/FAIL summary:

1. project.yaml validates against project.schema.yaml (incl. the abi: block,
   abi.schema.yaml).
2. module/module.wasm's sha256 matches project.yaml's metadata.buildHash, by
   rebuilding the guest module to a scratch path with the same TinyGo
   invocation as `make wasm.rebuild-verify` (mk/wasm.mk).
3. project.yaml's abi.exports match module/module.wasm's actual exports, by
   running module/abi_manifest_test.go's TestHostLoadABIManifestExportsPresent
   (go test).
4. MANIFEST.sha256 matches the working tree (same as `make manifest-verify`).
5. Provenance fields (createdBy, validatedBy, cicSign, cicSignedCA) are
   reported as OK / TBD / MISSING. This step does NOT perform any
   cryptographic signature verification.

Checks 1-4 gate the exit code; check 5 is informational only (see "make
verify-release" output and docs/contracts/en/release-artifact.md for what is
and is not verified).

Does not modify tools/infra.py, tools/compiler.py, or tools/finalize_release.py
— it imports load_and_resolve_schema/load_yaml from tools.infra and otherwise
re-runs the same external commands (tinygo, go test, sha256sum) that the
corresponding `make` targets use.
"""

import argparse
import hashlib
import subprocess  # nosec
import sys
import tempfile
from pathlib import Path

from jsonschema import ValidationError
from jsonschema import validate as jsonschema_validate

from .infra import ConfigurationError, load_and_resolve_schema, load_yaml

WASM_TARGET_DEFAULT = "wasip1"


def _print_result(step, ok, detail):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {step}")
    for line in detail.splitlines():
        print(f"       {line}")
    return ok


def check_schema(project_path, schema_path):
    """1. project.yaml validates against project.schema.yaml (incl. abi.schema.yaml via $ref)."""
    try:
        schema = load_and_resolve_schema(schema_path)
        instance = load_yaml(project_path)
        if instance is None:
            return _print_result(
                "1. project.yaml schema validation",
                False,
                f"{project_path} is empty.",
            )
        jsonschema_validate(instance=instance, schema=schema)
    except (ValidationError, ConfigurationError) as e:
        return _print_result("1. project.yaml schema validation", False, str(e))
    return _print_result(
        "1. project.yaml schema validation",
        True,
        f"{project_path} valid against {schema_path} (abi: via abi.schema.yaml).",
    )


def check_build_hash(project_path, module_dir, wasm_out, wasm_target):
    """2. Rebuild module.wasm to a scratch path and compare sha256 to metadata.buildHash.

    Same TinyGo invocation as mk/wasm.mk's wasm.rebuild-verify target.
    """
    instance = load_yaml(project_path)
    expected = (instance or {}).get("metadata", {}).get("buildHash", "")
    if not expected:
        return _print_result(
            "2. module.wasm buildHash",
            False,
            "metadata.buildHash is empty in project.yaml.",
        )

    with tempfile.TemporaryDirectory() as scratch_dir:
        scratch = Path(scratch_dir) / "module.wasm"
        cmd = [
            "tinygo",
            "build",
            "-o",
            str(scratch),
            "-target",
            wasm_target,
            "-scheduler=none",
            ".",
        ]
        proc = subprocess.run(
            cmd, cwd=module_dir, capture_output=True, text=True
        )  # nosec
        if proc.returncode != 0:
            return _print_result(
                "2. module.wasm buildHash",
                False,
                f"tinygo build failed:\n{proc.stderr}",
            )

        actual = hashlib.sha256(scratch.read_bytes()).hexdigest()

    if actual != expected:
        return _print_result(
            "2. module.wasm buildHash",
            False,
            f"rebuilt sha256:         {actual}\n"
            f"project.yaml buildHash: {expected}\n"
            f"Run 'make wasm.build' to refresh {wasm_out} and metadata.buildHash.",
        )
    return _print_result(
        "2. module.wasm buildHash",
        True,
        f"rebuilt sha256 == metadata.buildHash ({actual}).",
    )


def check_abi_exports(module_dir):
    """3. project.yaml abi.exports == module.wasm exports (module/abi_manifest_test.go)."""
    cmd = [
        "go",
        "test",
        "-run",
        "TestHostLoadABIManifestExportsPresent",
        "-v",
        ".",
    ]
    proc = subprocess.run(cmd, cwd=module_dir, capture_output=True, text=True)  # nosec
    if proc.returncode != 0:
        return _print_result(
            "3. abi.exports vs module.wasm exports",
            False,
            proc.stdout + proc.stderr,
        )
    return _print_result(
        "3. abi.exports vs module.wasm exports",
        True,
        "TestHostLoadABIManifestExportsPresent passed (go test).",
    )


def check_manifest(repo_root, manifest_path):
    """4. MANIFEST.sha256 matches the working tree (same as `make manifest-verify`)."""
    manifest = Path(manifest_path)
    if not manifest.is_file():
        return _print_result(
            "4. MANIFEST.sha256 integrity", False, f"{manifest_path} not found."
        )
    proc = subprocess.run(  # nosec
        ["sha256sum", "-c", manifest.name],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return _print_result(
            "4. MANIFEST.sha256 integrity",
            False,
            proc.stdout + proc.stderr,
        )
    return _print_result(
        "4. MANIFEST.sha256 integrity", True, "sha256sum -c MANIFEST.sha256 OK."
    )


def check_provenance(project_path):
    """5. Report provenance field status (OK / TBD / MISSING). Informational only.

    Does NOT verify any cryptographic signature.
    """
    instance = load_yaml(project_path) or {}
    metadata = instance.get("metadata", {})

    def field_status(value):
        if value is None:
            return "MISSING"
        if value == "TBD" or (isinstance(value, str) and value.startswith("TBD")):
            return "TBD"
        if isinstance(value, str) and value == "":
            return "MISSING"
        return "OK"

    fields = {
        "metadata.createdBy.name": (
            metadata.get("createdBy", {}).get("name")
            if isinstance(metadata.get("createdBy"), dict)
            else None
        ),
        "metadata.createdBy.certificate": (
            metadata.get("createdBy", {}).get("certificate")
            if isinstance(metadata.get("createdBy"), dict)
            else None
        ),
        "metadata.validatedBy.checksum": (
            metadata.get("validatedBy", {}).get("checksum")
            if isinstance(metadata.get("validatedBy"), dict)
            else None
        ),
        "metadata.checksum": metadata.get("checksum"),
        "metadata.sign": metadata.get("sign"),
        "metadata.cicSign": metadata.get("cicSign"),
        "metadata.cicSignedCA.certificate": (
            metadata.get("cicSignedCA", {}).get("certificate")
            if isinstance(metadata.get("cicSignedCA"), dict)
            else None
        ),
    }

    lines = []
    any_missing = False
    for name, value in fields.items():
        status = field_status(value)
        if status == "MISSING":
            any_missing = True
        lines.append(f"{name}: {status}")

    lines.append("")
    lines.append(
        "NOTE: this step does not verify any cryptographic signature (no Vault "
        "access). TBD fields are expected in a template/unreleased project.yaml "
        "and do not fail this check; a MISSING field indicates the metadata key "
        "itself is absent (schema violation, caught separately by check 1)."
    )

    return _print_result("5. provenance fields", not any_missing, "\n".join(lines))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="project.yaml")
    parser.add_argument("--schema", default="project.schema.yaml")
    parser.add_argument("--module-dir", default="module")
    parser.add_argument("--wasm-out", default="module/module.wasm")
    parser.add_argument("--manifest", default="MANIFEST.sha256")
    parser.add_argument(
        "--wasm-target",
        default=WASM_TARGET_DEFAULT,
        help="TinyGo -target (default: %(default)s, matches mk/wasm.mk WASM_TARGET).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(".").resolve()

    results = [
        check_schema(args.project, args.schema),
        check_build_hash(
            args.project, args.module_dir, args.wasm_out, args.wasm_target
        ),
        check_abi_exports(args.module_dir),
        check_manifest(repo_root, args.manifest),
    ]
    provenance_ok = check_provenance(args.project)

    print()
    if all(results):
        print("verify-release: PASS (checks 1-4). See check 5 for provenance status.")
        if not provenance_ok:
            print(
                "verify-release: check 5 reports a MISSING provenance field "
                "(informational, does not affect exit code)."
            )
        return 0

    print("verify-release: FAIL — see [FAIL] entries above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
