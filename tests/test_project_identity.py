"""The project's release identity must not change by accident.

`project.yaml` carries the component's identity (`metadata.name`,
`compiler_settings.component_name`) and its version. The component name decides
the release branch and tag names, and name and version are part of what the
release signatures cover. An accidental edit (a branch carrying another
component's identity, for example) must fail here, not surface at release time.

What this does NOT prove: that the existing checksum/sign/cicSign fields still
verify. That needs the signer certificates and the signing scheme of the
release that produced them; it is a separate check.
"""

import copy
import os
import re
import sys

import pytest
import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from tools.infra import ReleaseManager  # noqa: E402

# Changing the identity of this repository is a deliberate act: edit this
# constant in the same change, and say why.
EXPECTED_IDENTITY = "base"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def identity_problems(project: dict, expected: str = EXPECTED_IDENTITY) -> list:
    """Return what is wrong with the project's identity; empty means fine."""
    problems = []
    name = project.get("metadata", {}).get("name")
    component = project.get("compiler_settings", {}).get("component_name")
    version = project.get("metadata", {}).get("version")
    if name != expected:
        problems.append(f"metadata.name is {name!r}, expected {expected!r}")
    if component != expected:
        problems.append(f"component_name is {component!r}, expected {expected!r}")
    if name != component:
        problems.append(f"metadata.name {name!r} != component_name {component!r}")
    if not isinstance(version, str) or not SEMVER.match(version):
        problems.append(f"metadata.version {version!r} is not X.Y.Z")
    return problems


@pytest.fixture(scope="module")
def project():
    with open(os.path.join(PROJECT_ROOT, "project.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_project_identity_is_the_expected_one(project):
    assert identity_problems(project) == []


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda p: p["metadata"].update(name="iac-base"), "metadata.name"),
        (
            lambda p: p["compiler_settings"].update(component_name="iac-base"),
            "component_name",
        ),
        (lambda p: p["metadata"].update(version="0.7"), "not X.Y.Z"),
        (lambda p: p["metadata"].pop("version"), "not X.Y.Z"),
        (
            lambda p: (
                p["metadata"].update(name="other"),
                p["compiler_settings"].update(component_name="other"),
            ),
            "expected 'base'",
        ),
    ],
)
def test_an_identity_change_is_detected(project, mutate, fragment):
    """Negative: the check must be able to fail."""
    changed = copy.deepcopy(project)
    mutate(changed)
    problems = identity_problems(changed)
    assert problems, "the mutation was not detected"
    assert any(fragment in p for p in problems), problems


def test_release_branch_names_follow_the_component(project):
    """The component name is what names the release branch (tag names are not checked here)."""
    manager = ReleaseManager.__new__(ReleaseManager)
    component = project["compiler_settings"]["component_name"]
    assert manager._release_branch_name("1.2.3", component) == "base/releases/v1.2.3"
    # A component named 'main' is the only one without a prefix.
    assert manager._release_branch_name("1.2.3", "main") == "releases/v1.2.3"
