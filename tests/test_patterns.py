"""
Test suite for pattern database validation.

This test suite validates:
1. Pattern files exist and are accessible
2. All patterns conform to JSON schema
3. All regex patterns compile without errors
4. Pattern IDs are unique across all files
5. Test examples match/don't match as expected
"""

import pytest
import yaml
import json
import re
from pathlib import Path
from jsonschema import validate, ValidationError

PATTERNS_DIR = Path(__file__).parent.parent / "patterns"
SCHEMA_PATH = PATTERNS_DIR / "schema.json"

REQUIRED_PATTERN_FILES = [
    "dangerous_commands.yaml",
    "safe_commands.yaml",
    "dangerous_reads.yaml",
    "sensitive_reads.yaml",
    "safe_reads.yaml",
]


def test_patterns_directory_exists():
    """Verify patterns directory exists."""
    assert PATTERNS_DIR.exists(), f"Patterns directory not found: {PATTERNS_DIR}"
    assert PATTERNS_DIR.is_dir(), f"Patterns path is not a directory: {PATTERNS_DIR}"


def test_schema_file_exists():
    """Verify schema.json exists."""
    assert SCHEMA_PATH.exists(), f"Schema file not found: {SCHEMA_PATH}"


def test_pattern_files_exist():
    """Verify all required pattern files exist."""
    for filename in REQUIRED_PATTERN_FILES:
        file_path = PATTERNS_DIR / filename
        assert file_path.exists(), f"Missing pattern file: {filename}"


def test_schema_is_valid_json():
    """Verify schema.json is valid JSON."""
    try:
        with open(SCHEMA_PATH) as f:
            json.load(f)
    except json.JSONDecodeError as e:
        pytest.fail(f"Schema is not valid JSON: {e}")


def test_patterns_validate_against_schema():
    """Verify all patterns conform to JSON schema."""
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                pytest.fail(f"{pattern_file.name} is not valid YAML: {e}")

        try:
            validate(instance=data, schema=schema)
        except ValidationError as e:
            pytest.fail(f"{pattern_file.name} failed schema validation: {e.message}")


def test_all_regexes_compile():
    """Verify all regex patterns compile without errors."""
    errors = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id', 'UNKNOWN')
            regex_str = pattern.get('regex', '')

            try:
                re.compile(regex_str)
            except re.error as e:
                errors.append(f"{pattern_file.name}:{pattern_id} - {e}")

    if errors:
        pytest.fail(f"Invalid regex patterns:\n" + "\n".join(errors))


def test_pattern_ids_are_unique():
    """Verify pattern IDs are unique across all files."""
    all_ids = {}
    duplicates = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id')
            if not pattern_id:
                continue

            if pattern_id in all_ids:
                duplicates.append(
                    f"Duplicate ID '{pattern_id}' in {pattern_file.name} "
                    f"(also in {all_ids[pattern_id]})"
                )
            else:
                all_ids[pattern_id] = pattern_file.name

    if duplicates:
        pytest.fail(f"Duplicate pattern IDs found:\n" + "\n".join(duplicates))


def test_pattern_ids_follow_naming_convention():
    """Verify pattern IDs use SCREAMING_SNAKE_CASE."""
    invalid_ids = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id', '')
            # Should be all uppercase with underscores
            if not re.match(r'^[A-Z][A-Z0-9_]*$', pattern_id):
                invalid_ids.append(f"{pattern_file.name}:{pattern_id}")

    if invalid_ids:
        pytest.fail(
            f"Invalid pattern IDs (must be SCREAMING_SNAKE_CASE):\n"
            + "\n".join(invalid_ids)
        )


def test_required_fields_present():
    """Verify all patterns have required fields."""
    required_fields = ['id', 'regex', 'message', 'severity', 'category']
    missing_fields = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for i, pattern in enumerate(data.get('patterns', [])):
            pattern_id = pattern.get('id', f'pattern_{i}')
            for field in required_fields:
                if field not in pattern:
                    missing_fields.append(
                        f"{pattern_file.name}:{pattern_id} missing '{field}'"
                    )

    if missing_fields:
        pytest.fail(f"Missing required fields:\n" + "\n".join(missing_fields))


def test_severity_values_are_valid():
    """Verify severity values are from allowed set."""
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    invalid_severities = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id', 'UNKNOWN')
            severity = pattern.get('severity', '')

            if severity not in valid_severities:
                invalid_severities.append(
                    f"{pattern_file.name}:{pattern_id} has invalid severity '{severity}'"
                )

    if invalid_severities:
        pytest.fail(f"Invalid severity values:\n" + "\n".join(invalid_severities))


def test_category_values_are_valid():
    """Verify category values are from allowed set."""
    valid_categories = {
        'filesystem', 'network', 'credential', 'system', 'process',
        'persistence', 'execution', 'exfiltration'
    }
    invalid_categories = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id', 'UNKNOWN')
            category = pattern.get('category', '')

            if category not in valid_categories:
                invalid_categories.append(
                    f"{pattern_file.name}:{pattern_id} has invalid category '{category}'"
                )

    if invalid_categories:
        pytest.fail(f"Invalid category values:\n" + "\n".join(invalid_categories))


def test_pattern_examples_match_correctly():
    """Verify pattern examples match/don't match as expected."""
    failures = []

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        # Determine if this is a safe patterns file (uses match) or dangerous (uses search)
        is_safe_patterns = 'safe' in pattern_file.name

        with open(pattern_file) as f:
            data = yaml.safe_load(f)

        for pattern in data.get('patterns', []):
            pattern_id = pattern.get('id', 'UNKNOWN')
            regex_str = pattern.get('regex', '')

            try:
                regex = re.compile(regex_str)
            except re.error:
                # Regex compilation is tested separately
                continue

            for example in pattern.get('examples', []):
                command = example.get('command', '')
                should_match = example.get('should_match', False)

                # Safe patterns use match (start of string), dangerous use search (anywhere)
                if is_safe_patterns:
                    matches = bool(regex.match(command))
                else:
                    matches = bool(regex.search(command))

                if matches != should_match:
                    failures.append(
                        f"{pattern_file.name}:{pattern_id}\n"
                        f"  Command: {command}\n"
                        f"  Expected: {should_match}, Got: {matches}"
                    )

    if failures:
        pytest.fail(f"Pattern example failures:\n" + "\n".join(failures))


def test_pattern_count():
    """Verify we have the expected number of patterns."""
    total_patterns = 0

    for pattern_file in PATTERNS_DIR.glob("*.yaml"):
        if pattern_file.name == "schema.json":
            continue

        with open(pattern_file) as f:
            data = yaml.safe_load(f)
            total_patterns += len(data.get('patterns', []))

    # We expect 262 migrated patterns (180 dangerous commands + 71 dangerous reads + 11 sensitive reads)
    # Safe patterns (78 commands + safe reads) remain hardcoded in hooks by design
    assert total_patterns == 262, f"Expected 262 patterns, found {total_patterns}"

    print(f"\n✅ Total patterns loaded: {total_patterns}")
