import pytest
from defusedxml import DTDForbidden, EntitiesForbidden

from heisenberg import sbom_parser as sp


@pytest.mark.parametrize(
    "raw, expected",
    [("GoLang", "go"), ("rust", "cargo"), ("NPM", "npm"), ("pypi", "pypi")],
)
def test_normalize_ecosystem(raw, expected):
    assert sp.normalize_ecosystem(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("node_modules/foo/node_modules/@scope/bar", "@scope/bar"),
        ("node_modules/left-pad", "left-pad"),
        ("requests", "requests"),
    ],
)
def test_clean_package_name(raw, expected):
    assert sp.clean_package_name(raw) == expected


@pytest.mark.parametrize(
    "name, fmt",
    [
        ("cyclonedx.json", "cyclonedx_json"),
        ("cyclonedx.xml", "cyclonedx_xml"),
        ("spdx.json", "spdx_json"),
        ("spdx.xml", "spdx_xml"),
        ("sbom.csv", "csv"),
    ],
)
def test_detect_format(fixtures_dir, name, fmt):
    assert sp.detect_format(str(fixtures_dir / name)) == fmt


def test_detect_format_rejects_unknown(fixtures_dir, tmp_path):
    with pytest.raises(ValueError):
        sp.detect_format(str(fixtures_dir / "unknown.json"))
    other = tmp_path / "sbom.txt"
    other.write_text("hello")
    with pytest.raises(ValueError):
        sp.detect_format(str(other))


def test_detect_format_invalid_json_raises_value_error(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError):
        sp.detect_format(str(bad))


def test_parse_cyclonedx_json(fixtures_dir):
    pkgs = sp.parse_sbom(str(fixtures_dir / "cyclonedx.json"))
    assert pkgs == [
        {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "license": "MIT"},
        {"name": "requests", "version": "2.32.3", "ecosystem": "pypi", "license": "Apache-2.0 OR MIT"},
        {"name": "github.com/pkg/errors", "version": "v0.9.1", "ecosystem": "go", "license": "N/A"},
        {"name": "mystery", "version": "1.0.0", "ecosystem": "unknown", "license": "N/A"},
    ]


def test_parse_cyclonedx_xml(fixtures_dir):
    pkgs = sp.parse_sbom(str(fixtures_dir / "cyclonedx.xml"))
    assert pkgs == [
        {"name": "serde", "version": "1.0.200", "ecosystem": "cargo", "license": "MIT"},
        {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "license": "Custom License"},
    ]


def test_parse_spdx_json(fixtures_dir):
    pkgs = sp.parse_sbom(str(fixtures_dir / "spdx.json"))
    assert pkgs == [
        {"name": "flask", "version": "3.0.0", "ecosystem": "pypi", "license": "BSD-3-Clause"},
        {"name": "tokio", "version": "1.37.0", "ecosystem": "cargo", "license": "MIT"},
    ]


def test_parse_spdx_xml(fixtures_dir):
    pkgs = sp.parse_sbom(str(fixtures_dir / "spdx.xml"))
    assert pkgs == [
        {"name": "express", "version": "4.19.2", "ecosystem": "npm", "license": "MIT"},
        {"name": "golang.org/x/text", "version": "v0.14.0", "ecosystem": "go", "license": "BSD-3-Clause"},
    ]


def test_parse_csv(fixtures_dir):
    pkgs = sp.parse_sbom(str(fixtures_dir / "sbom.csv"))
    names = [(p["name"], p["ecosystem"]) for p in pkgs]
    assert ("serde", "cargo") in names
    assert ("github.com/pkg/errors", "go") in names
    assert all(p["name"] != "incomplete" for p in pkgs), "rows without a version must be skipped"
    assert len(pkgs) == 5


# --- Security: untrusted vendor SBOMs must not be able to trigger XXE / entity expansion ---

def test_xml_external_entities_are_rejected(fixtures_dir):
    path = str(fixtures_dir / "xxe.xml")
    with pytest.raises((EntitiesForbidden, DTDForbidden, ValueError)):
        sp.parse_cyclonedx_xml(path)


def test_xml_entity_expansion_is_rejected(fixtures_dir):
    path = str(fixtures_dir / "billion_laughs.xml")
    with pytest.raises((EntitiesForbidden, DTDForbidden, ValueError)):
        sp.parse_cyclonedx_xml(path)
