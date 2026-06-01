"""Core linting logic for OSAC Add-On collections."""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Finding:
    check: str
    severity: str  # "error" or "warning"
    message: str
    path: str = ""


VALID_EVENTS = {
    "pre_create", "create", "post_create",
    "pre_update", "update", "post_update",
    "pre_delete", "delete", "post_delete",
    "signal",
}

VALID_PHASES = {"pre", "main", "post"}

RESOURCE_ACTION_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]*\.(pre_create|create|post_create|pre_update|update|post_update|pre_delete|delete|post_delete|signal)\.(pre|main|post)$"
)

INTERNAL_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def _load_yaml(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def lint_collection(collection_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(_check_galaxy(collection_path))
    findings.extend(_check_addon_manifest(collection_path))
    findings.extend(_check_roles(collection_path))
    findings.extend(_check_playbooks(collection_path))
    findings.extend(_check_rollback_completeness(collection_path))

    return findings


def _check_galaxy(path: Path) -> list[Finding]:
    galaxy = path / "galaxy.yml"
    if not galaxy.exists():
        return [Finding("galaxy", "error", "galaxy.yml not found", str(galaxy))]

    data = _load_yaml(galaxy)
    if not data:
        return [Finding("galaxy", "error", "galaxy.yml is not valid YAML", str(galaxy))]

    findings = []
    for field_name in ("namespace", "name", "version"):
        if field_name not in data:
            findings.append(Finding("galaxy", "error", f"Missing required field: {field_name}", str(galaxy)))

    return findings


def _is_internal_role(role_dir: Path) -> bool:
    osac_yaml = role_dir / "meta" / "osac.yaml"
    if not osac_yaml.exists():
        return False
    data = _load_yaml(osac_yaml)
    return bool(data and data.get("internal"))


def _is_resource_action_role(role_dir: Path) -> bool:
    if _is_internal_role(role_dir):
        return False
    return bool(RESOURCE_ACTION_PATTERN.match(role_dir.name))


def _has_resource_action_roles(path: Path) -> bool:
    roles_dir = path / "roles"
    if not roles_dir.is_dir():
        return False
    return any(_is_resource_action_role(d) for d in roles_dir.iterdir() if d.is_dir())


def _check_addon_manifest(path: Path) -> list[Finding]:
    addon = path / "meta" / "addon.yaml"
    if not addon.exists():
        if _has_resource_action_roles(path):
            return [Finding("addon", "error", "meta/addon.yaml not found (collection has ResourceAction roles)", str(addon))]
        return [Finding("addon", "warning", "meta/addon.yaml not found (utility/meta collection)", str(addon))]

    data = _load_yaml(addon)
    if not data:
        return [Finding("addon", "error", "meta/addon.yaml is not valid YAML", str(addon))]

    findings = []
    for field_name in ("name", "display_name", "version"):
        if field_name not in data:
            findings.append(Finding("addon", "error", f"Missing required field: {field_name}", str(addon)))

    if "resource_types" not in data:
        findings.append(Finding("addon", "warning", "No resource_types declared", str(addon)))
    elif not isinstance(data["resource_types"], list):
        findings.append(Finding("addon", "error", "resource_types must be a list", str(addon)))
    else:
        for rt in data["resource_types"]:
            if "name" not in rt:
                findings.append(Finding("addon", "error", "resource_type entry missing 'name'", str(addon)))
            if "scope" not in rt:
                findings.append(Finding("addon", "error", f"resource_type '{rt.get('name', '?')}' missing 'scope'", str(addon)))

    return findings


def _check_roles(path: Path) -> list[Finding]:
    roles_dir = path / "roles"
    if not roles_dir.is_dir():
        return [Finding("roles", "warning", "No roles/ directory found", str(roles_dir))]

    findings = []
    for role_dir in sorted(roles_dir.iterdir()):
        if not role_dir.is_dir():
            continue

        role_name = role_dir.name

        if _is_internal_role(role_dir):
            if not INTERNAL_ROLE_PATTERN.match(role_name):
                findings.append(Finding("naming", "warning", f"Internal role '{role_name}' has non-standard name", str(role_dir)))
            continue

        if RESOURCE_ACTION_PATTERN.match(role_name):
            findings.extend(_check_resource_action_role(role_dir))
        elif INTERNAL_ROLE_PATTERN.match(role_name):
            findings.append(Finding("naming", "warning",
                f"Role '{role_name}' is not a ResourceAction (<resource>.<event>.<phase>) and not marked internal",
                str(role_dir)))
        else:
            findings.append(Finding("naming", "error",
                f"Role '{role_name}' does not match any valid naming pattern",
                str(role_dir)))

    return findings


def _check_resource_action_role(role_dir: Path) -> list[Finding]:
    findings = []
    role_name = role_dir.name

    findings.extend(_check_role_entry_point(role_dir))
    findings.extend(_check_role_metadata(role_dir))

    return findings


def _check_role_entry_point(role_dir: Path) -> list[Finding]:
    tasks_dir = role_dir / "tasks"
    if not tasks_dir.is_dir():
        return [Finding("tasks", "error", f"Role '{role_dir.name}' missing tasks/ directory", str(tasks_dir))]

    main_yml = tasks_dir / "main.yml"
    main_yaml = tasks_dir / "main.yaml"
    if not main_yml.exists() and not main_yaml.exists():
        return [Finding("tasks", "error", f"Role '{role_dir.name}' missing tasks/main.yml entry point", str(tasks_dir))]

    return []


def _check_role_metadata(role_dir: Path) -> list[Finding]:
    osac_yaml = role_dir / "meta" / "osac.yaml"
    if not osac_yaml.exists():
        return [Finding("metadata", "error", f"Role '{role_dir.name}' missing meta/osac.yaml", str(osac_yaml))]

    data = _load_yaml(osac_yaml)
    if not data:
        return [Finding("metadata", "error", f"Role '{role_dir.name}' meta/osac.yaml is not valid YAML", str(osac_yaml))]

    findings = []

    if "resource_type" not in data:
        findings.append(Finding("metadata", "error", f"Role '{role_dir.name}' missing resource_type in meta/osac.yaml", str(osac_yaml)))

    if "event" not in data:
        findings.append(Finding("metadata", "error", f"Role '{role_dir.name}' missing event in meta/osac.yaml", str(osac_yaml)))
    elif data["event"].lower() not in VALID_EVENTS:
        findings.append(Finding("metadata", "error",
            f"Role '{role_dir.name}' has invalid event '{data['event']}' (valid: {', '.join(sorted(VALID_EVENTS))})",
            str(osac_yaml)))

    if "phase" not in data:
        findings.append(Finding("metadata", "error", f"Role '{role_dir.name}' missing phase in meta/osac.yaml", str(osac_yaml)))
    elif data["phase"].lower() not in VALID_PHASES:
        findings.append(Finding("metadata", "error",
            f"Role '{role_dir.name}' has invalid phase '{data['phase']}' (valid: {', '.join(sorted(VALID_PHASES))})",
            str(osac_yaml)))

    parts = role_dir.name.split(".")
    if len(parts) == 3 and "event" in data and "phase" in data:
        expected_event = parts[1]
        expected_phase = parts[2]
        if data["event"].lower() != expected_event:
            findings.append(Finding("metadata", "error",
                f"Role '{role_dir.name}' event '{data['event']}' does not match directory name segment '{expected_event}'",
                str(osac_yaml)))
        if data["phase"].lower() != expected_phase:
            findings.append(Finding("metadata", "error",
                f"Role '{role_dir.name}' phase '{data['phase']}' does not match directory name segment '{expected_phase}'",
                str(osac_yaml)))

    if "event" in data and data["event"].lower() == "create":
        if "outputs" not in data or not data["outputs"]:
            findings.append(Finding("metadata", "warning",
                f"Role '{role_dir.name}' is a Create action but declares no outputs",
                str(osac_yaml)))

    if "outputs" in data and isinstance(data["outputs"], list):
        for output in data["outputs"]:
            if "name" not in output:
                findings.append(Finding("metadata", "error", f"Role '{role_dir.name}' output entry missing 'name'", str(osac_yaml)))
            if "type" not in output:
                findings.append(Finding("metadata", "warning", f"Role '{role_dir.name}' output '{output.get('name', '?')}' missing 'type'", str(osac_yaml)))
            if "description" not in output:
                findings.append(Finding("metadata", "warning", f"Role '{role_dir.name}' output '{output.get('name', '?')}' missing 'description'", str(osac_yaml)))

    if "parameters" in data and isinstance(data["parameters"], list):
        for param in data["parameters"]:
            if "name" not in param:
                findings.append(Finding("metadata", "error", f"Role '{role_dir.name}' parameter entry missing 'name'", str(osac_yaml)))
            if "type" not in param:
                findings.append(Finding("metadata", "warning", f"Role '{role_dir.name}' parameter '{param.get('name', '?')}' missing 'type'", str(osac_yaml)))

    return findings


def _check_playbooks(path: Path) -> list[Finding]:
    playbooks_dir = path / "playbooks"
    addon_yaml = path / "meta" / "addon.yaml"

    addon_data = _load_yaml(addon_yaml) if addon_yaml.exists() else None
    has_resource_types = addon_data and addon_data.get("resource_types")

    if not playbooks_dir.is_dir():
        if has_resource_types:
            return [Finding("playbooks", "warning", "Collection declares resource_types but has no playbooks/ directory", str(playbooks_dir))]
        return []

    findings = []
    playbook_files = list(playbooks_dir.glob("*.yml")) + list(playbooks_dir.glob("*.yaml"))

    has_create = any(f.stem == "create" for f in playbook_files)
    has_delete = any(f.stem == "delete" for f in playbook_files)

    if has_create and not has_delete:
        findings.append(Finding("playbooks", "warning", "create.yml exists without matching delete.yml", str(playbooks_dir)))
    if has_delete and not has_create:
        findings.append(Finding("playbooks", "warning", "delete.yml exists without matching create.yml", str(playbooks_dir)))

    for pb in playbook_files:
        content = pb.read_text()
        if "ansible_eda" in content:
            findings.append(Finding("eda", "warning", f"Playbook references ansible_eda (legacy EDA pattern)", str(pb)))

    return findings


def _check_rollback_completeness(path: Path) -> list[Finding]:
    roles_dir = path / "roles"
    if not roles_dir.is_dir():
        return []

    findings = []
    resources_with_create = set()
    resources_with_delete = set()

    for role_dir in roles_dir.iterdir():
        if not role_dir.is_dir() or not _is_resource_action_role(role_dir):
            continue

        parts = role_dir.name.split(".")
        if len(parts) != 3:
            continue

        resource, event, phase = parts
        if event == "create" and phase == "main":
            resources_with_create.add(resource)
        elif event == "delete" and phase == "main":
            resources_with_delete.add(resource)

    missing_delete = resources_with_create - resources_with_delete
    for resource_name in sorted(missing_delete):
        findings.append(Finding(
            "rollback", "warning",
            f"Resource '{resource_name}' has create.main but no matching delete.main (rollback incomplete)",
            str(roles_dir),
        ))

    return findings
