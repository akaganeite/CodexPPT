"""Schema loading and a dependency-free JSON-schema validator."""

from __future__ import annotations

from typing import Any

from claudeagent.common import FINAL_RESULT_SCHEMA, load_json


DETERMINATE_STATUSES = {"present", "absent", "not_affected"}
INCONCLUSIVE_REASONS = {
    "none",
    "insufficient_metadata",
    "no_binary_anchor",
    "stripped_or_optimized",
    "conflicting_evidence",
    "tool_failure",
    "unsupported_binary",
    "insufficient_tool_budget",
    "not_applicable_uncertain",
    "other",
}


def load_final_result_schema() -> dict[str, Any]:
    schema = load_json(FINAL_RESULT_SCHEMA)
    if not isinstance(schema, dict):
        raise ValueError(f"final result schema is not an object: {FINAL_RESULT_SCHEMA}")
    return schema


def resolve_schema_refs(schema: Any, root_schema: dict[str, Any]) -> Any:
    if isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ValueError(f"unsupported schema ref: {ref!r}")
        target: Any = root_schema
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or part not in target:
                raise ValueError(f"schema ref not found: {ref!r}")
            target = target[part]
        return resolve_schema_refs(target, root_schema)
    if isinstance(schema, dict):
        return {key: resolve_schema_refs(value, root_schema) for key, value in schema.items()}
    if isinstance(schema, list):
        return [resolve_schema_refs(item, root_schema) for item in schema]
    return schema


def final_tool_parameters_schema() -> dict[str, Any]:
    schema = load_final_result_schema()
    defs = schema.get("$defs") if isinstance(schema.get("$defs"), dict) else {}
    submit_schema = defs.get("submit_detection_result")
    if not isinstance(submit_schema, dict):
        raise ValueError("final result schema is missing $defs.submit_detection_result")
    return resolve_schema_refs(submit_schema, schema)


def schema_type_name(type_spec: Any) -> str:
    if isinstance(type_spec, list):
        return " or ".join(str(item) for item in type_spec)
    return str(type_spec)


def value_matches_schema_type(value: Any, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "null":
        return value is None
    return True


def validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} is not one of {schema['enum']!r}")

    type_spec = schema.get("type")
    if type_spec is not None:
        expected_types = type_spec if isinstance(type_spec, list) else [type_spec]
        if not any(value_matches_schema_type(value, str(item)) for item in expected_types):
            errors.append(f"{path}: expected {schema_type_name(type_spec)}, got {type(value).__name__}")
            return errors

    if isinstance(value, dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: missing required property")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key in properties:
                child_schema = properties[key]
            elif additional is False:
                errors.append(f"{child_path}: additional property is not allowed")
                continue
            elif isinstance(additional, dict):
                child_schema = additional
            else:
                continue
            if isinstance(child_schema, dict):
                errors.extend(validate_json_schema(item, child_schema, child_path))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append(f"{path}: expected at least {schema['minItems']} items, got {len(value)}")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append(f"{path}: expected at most {schema['maxItems']} items, got {len(value)}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(validate_json_schema(item, item_schema, f"{path}[{index}]"))

    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{path}: expected string length >= {schema['minLength']}, got {len(value)}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{path}: expected string length <= {schema['maxLength']}, got {len(value)}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: expected value >= {schema['minimum']}, got {value}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: expected value <= {schema['maximum']}, got {value}")

    return errors
