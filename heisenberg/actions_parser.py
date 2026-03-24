# heisenberg/actions_parser.py

import re
import requests
import yaml
from base64 import b64decode
from actions_checker import _github_headers


_SHA_RE = re.compile(r'^[0-9a-f]{40}$')

def fetch_workflow_files(org: str, repo: str, token: str) -> list[dict]:
    headers = _github_headers(token)
    url = f"https://api.github.com/repos/{org}/{repo}/contents/.github/workflows"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code == 404:
        return []
    resp.raise_for_status()

    files = []
    for item in resp.json():
        if not item["name"].endswith((".yml", ".yaml")):
            continue
        file_resp = requests.get(item["url"], headers=headers, timeout=15)
        file_resp.raise_for_status()
        raw = b64decode(file_resp.json()["content"]).decode("utf-8")
        files.append({"name": item["name"], "path": item["path"], "content": raw})

    return files


def _collect_uses(node: object, results: list) -> None:
    if isinstance(node, dict):
        if "uses" in node and isinstance(node["uses"], str):
            results.append(node["uses"])
        for v in node.values():
            _collect_uses(v, results)
    elif isinstance(node, list):
        for item in node:
            _collect_uses(item, results)


def parse_uses_from_workflow(content: str) -> list[str]:
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    if not doc:
        return []
    results = []
    _collect_uses(doc, results)
    return results


def parse_action_ref(uses: str) -> dict:
    if uses.startswith("docker://"):
        return {
            "full_action": uses,
            "owner": None,
            "action_repo": None,
            "ref": None,
            "is_sha_pinned": False,
            "action_type": "docker",
        }

    if uses.startswith("./"):
        return {
            "full_action": uses,
            "owner": None,
            "action_repo": None,
            "ref": None,
            "is_sha_pinned": False,
            "action_type": "local",
        }

    if "@" in uses:
        action_path, ref = uses.rsplit("@", 1)
        parts = action_path.split("/")
        owner = parts[0] if len(parts) >= 1 else None
        action_repo = parts[1] if len(parts) >= 2 else None
        return {
            "full_action": uses,
            "owner": owner,
            "action_repo": action_repo,
            "ref": ref,
            "is_sha_pinned": bool(_SHA_RE.match(ref)),
            "action_type": "action",
        }

    return {
        "full_action": uses,
        "owner": None,
        "action_repo": None,
        "ref": None,
        "is_sha_pinned": False,
        "action_type": "unknown",
    }


def _is_internal_action(org: str, shared_repo: str, uses: str) -> bool:
    return uses.startswith(f"{org}/{shared_repo}/actions/")


def fetch_action_definition(org: str, shared_repo: str, uses: str, token: str) -> list[str]:
    headers = _github_headers(token)
    action_path = uses.split("@")[0].replace(f"{org}/{shared_repo}/", "")
    for filename in ("action.yml", "action.yaml"):
        url = f"https://api.github.com/repos/{org}/{shared_repo}/contents/{action_path}/{filename}"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.ok:
            raw = b64decode(resp.json()["content"]).decode("utf-8")
            return parse_uses_from_workflow(raw)
    return []


def extract_actions_from_repo(
    org: str, repo: str, token: str, shared_actions_repo: str | None = None
) -> list[dict]:
    workflow_files = fetch_workflow_files(org, repo, token)
    results = []

    for wf in workflow_files:
        uses_list = parse_uses_from_workflow(wf["content"])
        for uses in uses_list:
            if shared_actions_repo and _is_internal_action(org, shared_actions_repo, uses):
                for resolved_uses in fetch_action_definition(org, shared_actions_repo, uses, token):
                    parsed = parse_action_ref(resolved_uses)
                    if parsed["action_type"] == "local":
                        continue
                    results.append({
                        "repo": repo,
                        "workflow_file": wf["name"],
                        "resolved_via": uses,
                        **parsed,
                    })
            else:
                parsed = parse_action_ref(uses)
                results.append({
                    "repo": repo,
                    "workflow_file": wf["name"],
                    "resolved_via": None,
                    **parsed,
                })

    return results