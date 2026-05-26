#heisenberg/cargo_build_script.py

import io, tarfile, tomllib, requests

def fetch_crate_tarball_bytes(name: str, version: str, timeout=(15, 30)) -> bytes:
    url = f"https://crates.io/api/v1/crates/{name}/{version}/download"
    r = requests.get(
        url,
        headers={"User-Agent": "heisenberg-ssc-health-check"},
        timeout=timeout[1],
        allow_redirects=True,
    )
    r.raise_for_status()
    return r.content


def detect_build_script(tar_bytes: bytes) -> dict:
    """Look for build.rs anywhere in the crate tarball, including custom paths."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        members = {m.name: m for m in tf.getmembers()}
        cargo_toml_member = next(
            (m for name, m in members.items() if name.endswith("/Cargo.toml")),
            None,
        )
        if cargo_toml_member is not None:
            f = tf.extractfile(cargo_toml_member)
            if f:
                try:
                    cargo_data = tomllib.loads(f.read().decode("utf-8"))
                    custom = cargo_data.get("package", {}).get("build")
                    if isinstance(custom, str):
                        crate_root = cargo_toml_member.name.rsplit("/", 1)[0]
                        return {
                            "has_build_script": True,
                            "build_script_path": f"{crate_root}/{custom}",
                        }
                except Exception:
                    pass
        for name in members:
            if name.endswith("/build.rs") or name == "build.rs":
                return {"has_build_script": True, "build_script_path": name}
    return {"has_build_script": False, "build_script_path": ""}


def check_cargo_build_script(name: str, version: str) -> dict:
    blob = fetch_crate_tarball_bytes(name, version)
    return detect_build_script(blob)