"""Tests for osac-addon-lint core linting logic."""

import textwrap
from pathlib import Path

import pytest
import yaml

from osac_addon_lint.linter import Finding, lint_collection


@pytest.fixture
def tmp_collection(tmp_path):
    """Create a minimal valid collection scaffold."""
    (tmp_path / "galaxy.yml").write_text(yaml.dump({
        "namespace": "osac",
        "name": "test_provider",
        "version": "0.1.0",
    }))
    (tmp_path / "meta").mkdir()
    (tmp_path / "meta" / "addon.yaml").write_text(yaml.dump({
        "name": "osac-test-provider",
        "display_name": "Test Provider",
        "version": "0.1.0",
        "resource_types": [{"name": "Widget", "scope": "tenant"}],
    }))
    return tmp_path


def _make_resource_action_role(collection_path, role_name, osac_meta):
    role_dir = collection_path / "roles" / role_name
    (role_dir / "tasks").mkdir(parents=True)
    (role_dir / "meta").mkdir(parents=True)
    (role_dir / "tasks" / "main.yml").write_text("---\n- name: noop\n  ansible.builtin.debug:\n    msg: ok\n")
    (role_dir / "meta" / "main.yml").write_text("---\ndependencies: []\n")
    (role_dir / "meta" / "osac.yaml").write_text(yaml.dump(osac_meta))
    return role_dir


def _make_internal_role(collection_path, role_name):
    role_dir = collection_path / "roles" / role_name
    (role_dir / "tasks").mkdir(parents=True)
    (role_dir / "meta").mkdir(parents=True)
    (role_dir / "tasks" / "main.yml").write_text("---\n- name: noop\n  ansible.builtin.debug:\n    msg: ok\n")
    (role_dir / "meta" / "osac.yaml").write_text("internal: true\n")
    return role_dir


class TestGalaxyChecks:
    def test_missing_galaxy(self, tmp_path):
        findings = lint_collection(tmp_path)
        assert any(f.check == "galaxy" and f.severity == "error" for f in findings)

    def test_valid_galaxy(self, tmp_collection):
        findings = lint_collection(tmp_collection)
        assert not any(f.check == "galaxy" for f in findings)


class TestAddonManifest:
    def test_missing_addon_with_resource_roles(self, tmp_collection):
        (tmp_collection / "meta" / "addon.yaml").unlink()
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
            "outputs": [{"name": "id", "type": "string", "description": "Widget ID"}],
        })
        findings = lint_collection(tmp_collection)
        assert any(f.check == "addon" and f.severity == "error" for f in findings)

    def test_missing_addon_utility_collection(self, tmp_collection):
        (tmp_collection / "meta" / "addon.yaml").unlink()
        _make_internal_role(tmp_collection, "helper")
        findings = lint_collection(tmp_collection)
        addon_findings = [f for f in findings if f.check == "addon"]
        assert all(f.severity == "warning" for f in addon_findings)


class TestRoleNaming:
    def test_valid_resource_action_name(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
            "outputs": [{"name": "id", "type": "string", "description": "Widget ID"}],
        })
        findings = lint_collection(tmp_collection)
        assert not any(f.check == "naming" for f in findings)

    def test_unmarked_non_resource_action_role(self, tmp_collection):
        role_dir = tmp_collection / "roles" / "helper_role"
        (role_dir / "tasks").mkdir(parents=True)
        (role_dir / "tasks" / "main.yml").write_text("---\n- name: noop\n  ansible.builtin.debug:\n    msg: ok\n")
        findings = lint_collection(tmp_collection)
        assert any(f.check == "naming" and "not marked internal" in f.message for f in findings)

    def test_internal_role_skips_validation(self, tmp_collection):
        _make_internal_role(tmp_collection, "my_helper")
        findings = lint_collection(tmp_collection)
        assert not any(f.check == "naming" for f in findings)


class TestRoleMetadata:
    def test_missing_osac_yaml(self, tmp_collection):
        role_dir = tmp_collection / "roles" / "widget.create.main"
        (role_dir / "tasks").mkdir(parents=True)
        (role_dir / "tasks" / "main.yml").write_text("---\n")
        findings = lint_collection(tmp_collection)
        assert any(f.check == "metadata" and f.severity == "error" and "missing meta/osac.yaml" in f.message for f in findings)

    def test_missing_event_and_phase(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget",
        })
        findings = lint_collection(tmp_collection)
        assert any("missing event" in f.message for f in findings)
        assert any("missing phase" in f.message for f in findings)

    def test_invalid_event(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Build", "phase": "main",
        })
        findings = lint_collection(tmp_collection)
        assert any("invalid event" in f.message for f in findings)

    def test_event_mismatch_with_dirname(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Delete", "phase": "main",
            "outputs": [{"name": "id", "type": "string", "description": "ID"}],
        })
        findings = lint_collection(tmp_collection)
        assert any("does not match directory name" in f.message for f in findings)

    def test_create_without_outputs_warns(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
        })
        findings = lint_collection(tmp_collection)
        assert any("Create action but declares no outputs" in f.message for f in findings)


class TestEntryPoint:
    def test_missing_main_yml(self, tmp_collection):
        role_dir = tmp_collection / "roles" / "widget.create.main"
        (role_dir / "tasks").mkdir(parents=True)
        (role_dir / "meta").mkdir(parents=True)
        (role_dir / "tasks" / "create.yaml").write_text("---\n")
        (role_dir / "meta" / "osac.yaml").write_text(yaml.dump({
            "resource_type": "Widget", "event": "Create", "phase": "main",
        }))
        findings = lint_collection(tmp_collection)
        assert any("missing tasks/main.yml" in f.message for f in findings)


class TestPlaybooks:
    def test_create_without_delete_warns(self, tmp_collection):
        pb_dir = tmp_collection / "playbooks"
        pb_dir.mkdir()
        (pb_dir / "create.yml").write_text("---\n- name: Create\n  hosts: localhost\n")
        findings = lint_collection(tmp_collection)
        assert any("create.yml exists without matching delete.yml" in f.message for f in findings)

    def test_eda_reference_warns(self, tmp_collection):
        pb_dir = tmp_collection / "playbooks"
        pb_dir.mkdir()
        (pb_dir / "create.yml").write_text("---\n- name: Create\n  hosts: localhost\n  tasks:\n    - set_fact: x={{ ansible_eda.event }}\n")
        (pb_dir / "delete.yml").write_text("---\n")
        findings = lint_collection(tmp_collection)
        assert any(f.check == "eda" for f in findings)


class TestRollbackCompleteness:
    def test_create_without_delete_warns(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
            "outputs": [{"name": "id", "type": "string", "description": "ID"}],
        })
        findings = lint_collection(tmp_collection)
        assert any(f.check == "rollback" and "widget" in f.message for f in findings)

    def test_matched_create_delete_no_warning(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
            "outputs": [{"name": "id", "type": "string", "description": "ID"}],
        })
        _make_resource_action_role(tmp_collection, "widget.delete.main", {
            "resource_type": "Widget", "event": "Delete", "phase": "main",
            "outputs": [],
        })
        findings = lint_collection(tmp_collection)
        assert not any(f.check == "rollback" for f in findings)


class TestFullCollection:
    def test_clean_collection_passes(self, tmp_collection):
        _make_resource_action_role(tmp_collection, "widget.create.main", {
            "resource_type": "Widget", "event": "Create", "phase": "main",
            "priority": 100, "failure_policy": "Fail",
            "outputs": [{"name": "widget_id", "type": "string", "description": "Created widget ID"}],
        })
        _make_resource_action_role(tmp_collection, "widget.delete.main", {
            "resource_type": "Widget", "event": "Delete", "phase": "main",
            "priority": 100, "failure_policy": "Fail",
            "outputs": [],
        })
        _make_internal_role(tmp_collection, "shared_utils")
        pb_dir = tmp_collection / "playbooks"
        pb_dir.mkdir()
        (pb_dir / "create.yml").write_text("---\n- name: Create\n  hosts: localhost\n")
        (pb_dir / "delete.yml").write_text("---\n- name: Delete\n  hosts: localhost\n")

        findings = lint_collection(tmp_collection)
        errors = [f for f in findings if f.severity == "error"]
        assert len(errors) == 0, f"Unexpected errors: {[f.message for f in errors]}"
