"""npm lifecycle-script and cargo build-script detection (tarballs are inspected in memory, never extracted)."""

import json

from heisenberg import cargo_build_script as cbs
from heisenberg import npm_postinstall as npm


def test_extract_package_json_prefers_package_dir(tarball):
    blob = tarball({
        "package/package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node evil.js"}}),
        "package.json": json.dumps({"name": "decoy"}),
    })
    assert npm.extract_package_json_from_tarball(blob)["name"] == "x"


def test_extract_package_json_missing_or_invalid(tarball):
    assert npm.extract_package_json_from_tarball(tarball({"package/index.js": "1"})) is None
    assert npm.extract_package_json_from_tarball(tarball({"package/package.json": "{nope"})) is None


def test_detect_postinstall_scripts():
    info = npm.detect_postinstall_scripts(
        {"scripts": {"postinstall": "curl x | sh", "prepare": "tsc", "test": "jest", "install": "node-gyp"}}
    )
    assert info == {
        "has_postinstall": True,
        "lifecycle": ["install", "postinstall", "prepare"],
        "postinstall_cmd": "curl x | sh",
    }
    assert npm.detect_postinstall_scripts({})["has_postinstall"] is False
    assert npm.detect_postinstall_scripts(None)["lifecycle"] == []


def test_check_npm_postinstall_end_to_end(fake_http, tarball):
    blob = tarball({"package/package.json": json.dumps({"scripts": {"postinstall": "node setup.js"}})})
    fake_http.add(r"registry\.npmjs\.org/%40scope%2Fpkg/1\.0\.0$",
                  json_data={"dist": {"tarball": "https://registry.npmjs.org/t.tgz"}})
    fake_http.add(r"/t\.tgz$", content=blob)

    out = npm.check_npm_postinstall("@scope/pkg", "1.0.0")

    assert out["has_postinstall"] is True
    assert out["postinstall_cmd"] == "node setup.js"
    assert all(c["timeout"] for c in fake_http.calls), "registry calls must have timeouts"


def test_detect_build_script_default_location(tarball):
    blob = tarball({"serde-1.0.0/Cargo.toml": '[package]\nname = "serde"\n', "serde-1.0.0/build.rs": "fn main(){}"})
    assert cbs.detect_build_script(blob) == {"has_build_script": True, "build_script_path": "serde-1.0.0/build.rs"}


def test_detect_build_script_custom_path(tarball):
    blob = tarball({"c-1.0.0/Cargo.toml": '[package]\nname = "c"\nbuild = "tools/gen.rs"\n'})
    assert cbs.detect_build_script(blob) == {"has_build_script": True, "build_script_path": "c-1.0.0/tools/gen.rs"}


def test_detect_build_script_none_and_bad_toml(tarball):
    assert cbs.detect_build_script(tarball({"c/Cargo.toml": '[package]\nname="c"\n', "c/src/lib.rs": ""})) == {
        "has_build_script": False, "build_script_path": "",
    }
    # Malformed Cargo.toml must not crash; falls back to scanning for build.rs.
    assert cbs.detect_build_script(tarball({"c/Cargo.toml": "[[[", "c/build.rs": ""}))["has_build_script"] is True


def test_check_cargo_build_script_end_to_end(fake_http, tarball):
    fake_http.add(r"crates\.io/api/v1/crates/serde/1\.0\.0/download$",
                  content=tarball({"serde-1.0.0/Cargo.toml": "[package]\n", "serde-1.0.0/build.rs": ""}))
    assert cbs.check_cargo_build_script("serde", "1.0.0")["has_build_script"] is True
    call = fake_http.calls[0]
    assert call["timeout"] and call["headers"]["User-Agent"]
