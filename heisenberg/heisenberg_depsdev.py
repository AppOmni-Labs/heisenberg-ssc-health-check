# heisenberg/heisenberg_depsdev.py

import argparse
import urllib
import requests
import sys
import math
from datetime import datetime, timezone

from .npm_postinstall import check_npm_postinstall
from .cargo_build_script import check_cargo_build_script


BASE_URL = "https://api.deps.dev/v3" 

def parse_args():
    parser = argparse.ArgumentParser(description="Check package info using deps.dev")
    add_arguments(parser)
    return parser.parse_args()

def add_arguments(parser):
    parser.add_argument("mode", nargs="?", default="main_package", choices=["main_package"],
                        help="Only 'main_package' is supported.")
    parser.add_argument("-mgmt", "--mgmt", required=True, help="Package management system (e.g., pypi, npm, go, cargo)")
    parser.add_argument("-pkg", "--pkg", required=True, help="Package name")
    parser.add_argument("-v", "--version", required=True, help="Package version")

def fetch_npm_deprecated(package_manager, package_name, package_version):
    """Checks if npm package waas potentially deprecated."""
    if package_manager != "npm":
        return None
    npm_url = f"https://registry.npmjs.org/{package_name}/{package_version}"
    npm_resp = requests.get(npm_url)
    if npm_resp.status_code == 200:
        npm_data = npm_resp.json()
        return npm_data.get("deprecated", None)
    else:
        print(f"Warning: npm registry request failed with status {npm_resp.status_code}")
        return None

def fetch_pypi_deprecated(package_manager, package_name, package_version):
    """Checks if the pypi package was potentially deprecated."""
    if package_manager != "pypi":
        return None
    
    url = f"https://pypi.org/pypi/{package_name}/{package_version}/json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        
        data = resp.json()
        info = data.get("info", {}) or {}
        classifiers = info.get("classifiers", []) or []

        for c in classifiers:
            if c.strip().lower() == "development status :: 7 - inactive".lower():
                return "Inactive/Deprecated (Development Status :: 7 - Inactive)"

        return None
    except Exception:
        return None

def fetch_cargo_deprecated(package_manager, package_name, package_version):
    """Checks if the cargo package was potentially deprecated / yanked."""
    if package_manager != "cargo":
        return None
    url = f"https://crates.io/api/v1/crates/{package_name}/{package_version}"
    try:
        resp = requests.get(
            url, 
            headers={"User-Agent": "heisenberg-ssc-health-check (https://github.com/AppOmni-Labs/heisenberg-ssc-health-check)"},
            timeout=10, 
        )
        if resp.status_code != 200:
            return None
        version_info = resp.json().get("version", {}) or {}
        if version_info.get("yanked"):
            return "Yanked from crates.io"
        return None
    except Exception:
        return None

def fetch_version_data(base_url, package_manager, encoded_name, package_version):
    version_url = f"{base_url}/systems/{package_manager}/packages/{encoded_name}/versions/{package_version}"
    return requests.get(version_url)

def fetch_dependents_count(package_manager, encoded_name, package_version):
    """Fetch data on how many projects depend on the package version."""
    dependents_url = f"https://api.deps.dev/v3alpha/systems/{package_manager}/packages/{encoded_name}/versions/{package_version}:dependents"
    dependents_resp = requests.get(dependents_url)
    if dependents_resp.status_code == 200:
        return dependents_resp.json().get("dependentCount", "N/A")
    return "N/A"

def fetch_project_data_with_github_fallback(base_url, project_id):
    """Fetch data from deps.dev or github if deps.dev not available."""
    project_data = {}
    stars = 0
    forks = 0
    if not project_id:
        print("[INFO] No project ID found, skipping project-level metadata.")
        return project_data, stars, forks

    project_url = f"{base_url}/projects/{urllib.parse.quote(project_id, safe='')}"
    project_response = requests.get(project_url)
    if project_response.status_code == 200:
        project_data = project_response.json()
        return project_data, stars, forks

    print(f"[INFO] deps.dev project is not found (status {project_response.status_code})")
    if project_id.startswith("github.com"):
        try:
            owner_repo = project_id.replace("github.com/", "")
            gh_api_url = f"https://api.github.com/repos/{owner_repo}"
            gh_resp = requests.get(gh_api_url)
            if gh_resp.status_code == 200:
                gh_data = gh_resp.json()
                stars = gh_data.get("stargazers_count", 0)
                forks = gh_data.get("forks_count", 0)
            else:
                print(f"[WARN] Github API failed for {owner_repo} with {gh_resp.status_code}")
        except Exception as e:
            print(f"[ERROR] Exception during Github API fallback: {e}")
    return project_data, stars, forks

# TODO: Experimental, need to revise the formula and put more weight into Security and Maintanance
# deps.dev health score is too agressive and it would be better to soften the score a bit. Therefore,
# it makes sense to calculate our own score based on the metrics we care about the most.  
def compute_custom_health_score(parsed):
    try:
        stars = int(parsed["popularity_info_stars"])
        forks = int(parsed["popularity_info_forks"])
        maintained = float(parsed["maintenance_info"]) if parsed["maintenance_info"] != "N/A" else 0
        vulnerabilities = float(parsed["security_score"]) if parsed["security_score"] != "N/A" else 0
        dependents = int(parsed["dependents"]) if parsed["dependents"] != "N/A" else 0

        raw_pop = math.log1p(stars + forks)
        popularity_score = min((raw_pop / 2.5) * 10, 10)
        dependent_score = min((math.log1p(dependents) / 10) * 10, 10)

        health_score = (
            popularity_score * 0.25 +
            maintained * 0.2 +
            vulnerabilities * 0.3 +
            dependent_score * 0.25
        )
        computed = round(health_score, 1)

        if parsed["health_score"] not in {"N/A", "Not Found"}:
            try:
                package_score = float(parsed["health_score"])
                final_score = round((package_score + computed) / 2, 1)
                return final_score
            except ValueError:
                pass

        return computed

    except Exception:
        return "Unknown"
    
def check_package(package_manager, package_name, package_version):
    """Fetches package health."""   
    package_manager = package_manager.lower()  
    supported = {"pypi", "npm", "go", "cargo"}  
    if package_manager not in supported:  
        return {"error": f"manager '{package_manager}' not supported"}  
    
    encoded_name = urllib.parse.quote(package_name, safe='')  
    version_response = fetch_version_data(BASE_URL, package_manager, encoded_name, package_version) 

    deprecated = None
    if package_manager == "npm":
        deprecated = fetch_npm_deprecated(package_manager, package_name, package_version)
    elif package_manager == "pypi":
        deprecated = fetch_pypi_deprecated(package_manager, package_name, package_version)
    elif package_manager == "cargo":
        deprecated = fetch_cargo_deprecated(package_manager, package_name, package_version)

    if version_response.status_code != 200:  
        return {
            "package": package_name, "version": package_version,
            "health_score": "Not Found", "description": "N/A",
            "popularity_info_stars": "N/A", "popularity_info_forks": "N/A",
            "dependents": "N/A", "maintenance_info": "N/A",
            "security_info": "None", "security_score": "N/A",
            "deprecated": "N/A", "custom_health_score": "N/A",
            "published_at": "N/A",  
            "fresh_publish": "N/A" 
        }

    version_data = version_response.json()  
    related_projects = version_data.get("relatedProjects", [])  
    project_id = related_projects[0].get("projectKey", {}).get("id", "") if related_projects else ""  
    advisory_keys = version_data.get("advisoryKeys", []) 
    advisory_ids = [adv.get("id") for adv in advisory_keys]  
    dependent_count = fetch_dependents_count(package_manager, encoded_name, package_version)  

    published_at_iso = version_data.get("publishedAt")  
    fresh_flag = "N/A"
    if published_at_iso:
        try:
            dt = datetime.fromisoformat(published_at_iso.replace("Z", "+00:00"))
            hours_old = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
            fresh_flag = "Yes" if hours_old < 24.0 else "No"
        except Exception:
            fresh_flag = "N/A"

    project_data, stars, forks = fetch_project_data_with_github_fallback(BASE_URL, project_id) 
    scorecard = {c["name"]: c for c in project_data.get("scorecard", {}).get("checks", [])}  
    parsed = {  
        "health_score": project_data.get("scorecard", {}).get("overallScore", "N/A"),
        "description": project_data.get("description", "N/A"),
        "popularity_info_stars": project_data.get("starsCount", stars if stars else 0),
        "popularity_info_forks": project_data.get("forksCount", forks if forks else 0),
        "dependents": dependent_count,
        "maintenance_info": scorecard.get("Maintained", {}).get("score", "N/A"),
        "security_score": scorecard.get("Vulnerabilities", {}).get("score", "N/A"),
    }
    custom = compute_custom_health_score(parsed) 

    pkg_safe_name = package_name.replace("/", "%2F")  
    snyk_ecosystem, socket_ecosystem = map_ecosystems(package_manager)  
    deps_url = f"https://deps.dev/{package_manager}/{pkg_safe_name}/{package_version}"  
    snyk_url = f"https://snyk.io/advisor/{snyk_ecosystem}/{package_name}"  
    socket_url = f"https://socket.dev/{socket_ecosystem}/package/{package_name}"  

    return {
        "package": package_name, "version": package_version, **parsed,
        "security_info": f"{len(advisory_ids)}" if advisory_ids else "None",
        "security_advisories": ", ".join(advisory_ids) if advisory_ids else "N/A",
        "deprecated": deprecated, "custom_health_score": custom,
        "deps_url": deps_url, "snyk_url": snyk_url, "socket_url": socket_url,
        "published_at": published_at_iso or "N/A",
        "fresh_publish": fresh_flag 
    }

def map_ecosystems(package_manager):
    """Helper to map ecosystem."""
    if package_manager == "pypi":
        return "python", "pypi"
    elif package_manager == "npm":
        return "npm-package", "npm"
    elif package_manager == "go":
        return "golang", "go"
    elif package_manager == "cargo":
        return "cargo", "cargo"
    else:
        return package_manager, package_manager

def print_not_found_and_exit(package_name, package_version):
    print(f"Package: {package_name}")
    print(f"Version: {package_version}")
    print("Package Health Score: Not Found")
    print("Description: N/A")
    print("Popularity (Stars): N/A")
    print("Popularity (Forks): N/A")
    print("Dependents: N/A")
    print("Maintained Score: N/A")
    print("Security Advisory: None")
    print("Security Score (Vulnerabilities): N/A")
    print("Deprecated: N/A")
    print("Published At: N/A")          
    print("Fresh Publish (<24h): N/A")
    sys.exit(0)

def print_report(
    PACKAGE_NAME,
    PACKAGE_VERSION,
    project_data,
    stars,
    forks,
    dependent_count,
    advisory_ids,
    deprecated,
    PACKAGE_MANAGER,
    published_at_iso,     
    fresh_flag,
    npminfo=None,
    cargoinfo=None,
):
    """Prints report for fetched package and its version."""
    scorecard = {check["name"]: check for check in project_data.get("scorecard", {}).get("checks", [])}

    print(f"Package: {PACKAGE_NAME}")
    print(f"Version: {PACKAGE_VERSION}")
    print(f"Package Health Score: {project_data.get('scorecard', {}).get('overallScore', 'N/A')}")
    print(f"Description: {project_data.get('description', 'N/A')}")
    print(f"Popularity (Stars): {project_data.get('starsCount', stars if stars else 'N/A')}")
    print(f"Popularity (Forks): {project_data.get('forksCount', forks if forks else 'N/A')}")
    print(f"Dependents: {dependent_count}")
    print(f"Maintained Score: {scorecard.get('Maintained', {}).get('score', 'N/A')}")

    if advisory_ids:
        print(f"Security Advisory Count: {len(advisory_ids)}")
        print(f"Security Advisory IDs: {', '.join(advisory_ids)}")
    else:
        print("Security Advisory: None")
    print(f"Deprecated: {deprecated}")

    parsed = {
        "health_score": project_data.get("scorecard", {}).get("overallScore", "N/A"),
        "description": project_data.get("description", "N/A"),
        "popularity_info_stars": project_data.get("starsCount", 0),
        "popularity_info_forks": project_data.get("forksCount", 0),
        "dependents": dependent_count,
        "maintenance_info": scorecard.get("Maintained", {}).get("score", "N/A"),
        "security_score": scorecard.get("Vulnerabilities", {}).get("score", "N/A"),
    }
    custom_score = compute_custom_health_score(parsed)

    print(f"Custom Health Score: {custom_score}")
    print(f"Security Score (Vulnerabilities): {scorecard.get('Vulnerabilities', {}).get('score', 'N/A')}")

    print(f"Published At: {published_at_iso or 'N/A'}")
    print(f"Fresh Publish (<24h): {fresh_flag}")

    if PACKAGE_MANAGER == "npm":
        has_post = "Yes" if (npminfo and npminfo.get("has_postinstall")) else "No"
        lifecycle = ", ".join(npminfo.get("lifecycle", [])) if npminfo else ""
        post_cmd = (npminfo or {}).get("postinstall_cmd") or ""

        print(f"Has Postinstall: {has_post}")
        print(f"Lifecycle Scripts: {lifecycle or 'None'}")
        if has_post == "Yes":
            short_cmd = (post_cmd[:160] + "…") if len(post_cmd) > 160 else post_cmd
            print(f"Postinstall Cmd: {short_cmd or 'N/A'}")
    
    if PACKAGE_MANAGER == "cargo":
        has_build = "Yes" if (cargoinfo and cargoinfo.get("has_build_script")) else "No"
        build_path = (cargoinfo or {}).get("build_script_path") or ""
        print(f"Has Build Script (build.rs): {has_build}")
        if has_build == "Yes":
            print(f"Build Script Path: {build_path}")

    print("\n[Cross-Check URLs]")
    pkg_safe_name = PACKAGE_NAME.replace("/", "%2F")
    snyk_ecosystem, socket_ecosystem = map_ecosystems(PACKAGE_MANAGER)
    deps_url = f"https://deps.dev/{PACKAGE_MANAGER}/{pkg_safe_name}/{PACKAGE_VERSION}"
    snyk_url = f"https://snyk.io/advisor/{snyk_ecosystem}/{PACKAGE_NAME}"
    socket_url = f"https://socket.dev/{socket_ecosystem}/package/{PACKAGE_NAME}"
    print(f"deps.dev:    {deps_url}")
    print(f"Snyk:        {snyk_url}")
    print(f"Socket.dev:  {socket_url}")

def cli(args=None):  
    if args is None:           
        args = parse_args()  

    SUPPORTED_MANAGERS = {"pypi", "npm", "go", "cargo"}

    PACKAGE_MANAGER = args.mgmt.lower()
    if PACKAGE_MANAGER not in SUPPORTED_MANAGERS:
        print(f"Error: Package manager '{args.mgmt}' is not supported yet.")
        sys.exit(1)

    PACKAGE_NAME = args.pkg
    PACKAGE_VERSION = args.version
    ENCODED_PACKAGE_NAME = urllib.parse.quote(PACKAGE_NAME, safe='')

    deprecated = None
    if PACKAGE_MANAGER == "npm":
        deprecated = fetch_npm_deprecated(PACKAGE_MANAGER, PACKAGE_NAME, PACKAGE_VERSION)
    elif PACKAGE_MANAGER == "pypi":
        deprecated = fetch_pypi_deprecated(PACKAGE_MANAGER, PACKAGE_NAME, PACKAGE_VERSION)
    elif PACKAGE_MANAGER == "cargo":
        deprecated = fetch_cargo_deprecated(PACKAGE_MANAGER, PACKAGE_NAME, PACKAGE_VERSION)
    version_response = fetch_version_data(BASE_URL, PACKAGE_MANAGER, ENCODED_PACKAGE_NAME, PACKAGE_VERSION)

    if version_response.status_code != 200:
        print_not_found_and_exit(PACKAGE_NAME, PACKAGE_VERSION)

    version_data = version_response.json()
    related_projects = version_data.get("relatedProjects", [])
    project_id = related_projects[0].get("projectKey", {}).get("id", "") if related_projects else ""
    advisory_keys = version_data.get("advisoryKeys", [])
    advisory_ids = [adv.get("id") for adv in advisory_keys]

    dependent_count = fetch_dependents_count(PACKAGE_MANAGER, ENCODED_PACKAGE_NAME, PACKAGE_VERSION)
    project_data, stars, forks = fetch_project_data_with_github_fallback(BASE_URL, project_id)

    published_at_iso = version_data.get("publishedAt")
    fresh_flag = "N/A"
    if published_at_iso:
        try:
            dt = datetime.fromisoformat(published_at_iso.replace("Z", "+00:00"))
            hours_old = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
            fresh_flag = "Yes" if hours_old < 24.0 else "No"
        except Exception:
            fresh_flag = "N/A"

    npminfo = None
    if PACKAGE_MANAGER == "npm":
        try:
            npminfo = check_npm_postinstall(PACKAGE_NAME, PACKAGE_VERSION)
        except Exception as e:
            npminfo = {"has_postinstall": False, "lifecycle": [], "postinstall_cmd": "", "error": str(e)}

    cargoinfo = None
    if PACKAGE_MANAGER == "cargo":
        try:
            cargoinfo = check_cargo_build_script(PACKAGE_NAME, PACKAGE_VERSION)
        except Exception as e:
            cargoinfo = {"has_build_script": False, "build_script_path": "", "error": str(e)}

    print_report(
        PACKAGE_NAME=PACKAGE_NAME,
        PACKAGE_VERSION=PACKAGE_VERSION,
        project_data=project_data,
        stars=stars,
        forks=forks,
        dependent_count=dependent_count,
        advisory_ids=advisory_ids,
        deprecated=deprecated,
        PACKAGE_MANAGER=PACKAGE_MANAGER,
        published_at_iso=published_at_iso,  
        fresh_flag=fresh_flag,
        npminfo=npminfo,
        cargoinfo=cargoinfo,
    )

if __name__ == "__main__": 
    cli() 
