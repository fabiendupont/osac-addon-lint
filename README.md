# osac-addon-lint

Validate Ansible collections against the OSAC Add-On convention.

## Install

```bash
pip install osac-addon-lint
```

## Usage

```bash
osac-addon-lint /path/to/collection
osac-addon-lint /path/to/collection --strict
```

## Checks

| Check | Description |
|---|---|
| galaxy | galaxy.yml exists with required fields |
| addon | meta/addon.yaml exists with resource_types |
| metadata | Each role has meta/osac.yaml with resource_type |
| naming | Role names follow convention |
| tasks | Roles have create/delete entry points |
| playbooks | create.yml and delete.yml exist as pairs |
| rollback | Every create role has a matching delete |
| eda | No legacy ansible_eda references |
