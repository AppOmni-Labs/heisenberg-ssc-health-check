# heisenberg/bulk_check.py

import subprocess
import csv
import sys
import os

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import argparse

from .config import Settings

from .sbom_utils import (
    write_repos_file, load_repos_from_file,
    run_github_sbom_script, iter_selected_sboms,
    cleanup_sbom_dir
)


DEPS_MODULE = "heisenberg.heisenberg_depsdev" 

_settings = Settings()  

DEFAULT_ORG = _settings.org
SBOM_DIR = _settings.sbom_dir        
OUTPUT_CSV = _settings.output_csv    
TIMEOUT = _settings.timeout 

REPOS_FILE_NAME = _settings.repos_file_name  

MAX_WORKERS = _settings.max_workers  
PAUSE_EVERY = _settings.pause_every  
PAUSE = _settings.pause   

LABEL_MAP = {
    "Package Health Score": "health_score",
    "Description": "description",
    "Popularity (Stars)": "popularity_info_stars",
    "Popularity (Forks)": "popularity_info_forks",
    "Maintained Score": "maintenance_info",
    "Dependents": "dependents",
    "Security Advisory Count": "security_info",
    "Security Advisory IDs": "security_advisories",
    "Security Score (Vulnerabilities)": "security_score",
    "Deprecated": "deprecated",
    "Custom Health Score": "custom_health_score",
    # Cross-check URLs
    "deps.dev": "deps_url",
    "Snyk": "snyk_url",
    "Socket.dev": "socket_url",
}

def parse_output(stdout):
    data = {
       "health_score": "N/A",
       "description": "N/A",
       "popularity_info_stars": "N/A",
       "popularity_info_forks": "N/A",
      "maintenance_info": "N/A",
       "dependents": "N/A",
       "security_info": "N/A",
       "security_advisories": "N/A",
       "security_score": "N/A",
       "deprecated": "N/A",
       "custom_health_score": "N/A",
       "deps_url": "N/A",
       "snyk_url": "N/A",
       "socket_url": "N/A",
    }
    
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        field = LABEL_MAP.get(key)
        if field:
            data[field] = value or data[field]
    return data



def run_check(package_manager, package, version):
    try:
        
        cmd = [
            sys.executable, "-m",  
            "heisenberg.heisenberg_depsdev",  
            "main_package",
            "-mgmt", package_manager,
            "-pkg", package,
            "-v", version
        ]
        print(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TIMEOUT
        )

        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        parsed = parse_output(result.stdout)

        return parsed

    except subprocess.TimeoutExpired:
        return {k: "Timeout" for k in [
            "health_score", "description", "popularity_info_stars", "popularity_info_forks",
            "maintenance_info", "dependents", "security_info", "security_advisories",
            "security_score", "custom_health_score", "deprecated"
        ]}
    except Exception as e:
        return {k: f"Error: {e}" for k in [
            "health_score", "description", "popularity_info_stars", "popularity_info_forks",
            "maintenance_info", "dependents", "security_info", "security_advisories",
            "security_score", "custom_health_score", "deprecated"
        ]}
    

CSV_HEADER = [
    "repo_name", "package", "version", "language", "license", "health_score", "custom_health_score", "description",
    "popularity_info_stars", "popularity_info_forks", "maintenance_info", "dependents",
    "security_info", "security_advisories", "security_score", "deprecated",
    "deps_url", "snyk_url", "socket_url"
] 

def build_csv_row(repo_name, name, version, package_manager, license_info="N/A"):
    result = run_check(package_manager, name, version)
    return [
        repo_name, name, version, package_manager, license_info,
        result.get("health_score", "N/A"),
        result.get("custom_health_score", "N/A"),
        result.get("description", "N/A"),
        result.get("popularity_info_stars", "N/A"),
        result.get("popularity_info_forks", "N/A"),
        result.get("maintenance_info", "N/A"),
        result.get("dependents", "N/A"),
        result.get("security_info", "N/A"),
        result.get("security_advisories", "N/A"),
        result.get("security_score", "N/A"),
        result.get("deprecated", "N/A"),
        result.get("deps_url", "N/A"),
        result.get("snyk_url", "N/A"),
        result.get("socket_url", "N/A"), 
    ]

def process_tasks(tasks, writer):
    launch_count = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_pkg = {}
        for repo_name, name, version, package_manager, license_info in tasks:
            future = executor.submit(build_csv_row, repo_name, name, version, package_manager, license_info)
            future_to_pkg[future] = (name, version, package_manager)

            launch_count += 1
            if launch_count % PAUSE_EVERY == 0:
                time.sleep(PAUSE)

        for future in as_completed(future_to_pkg):
            name, version, package_manager = future_to_pkg[future]
            try:
                row_out = future.result()
            except Exception as e:
                print(f"[ERROR] Failed {name} {version} ({package_manager}): {e}")
                repo_name = tasks[0][0] if tasks else ""
                row_out = [
                    repo_name, name, version, package_manager, "N/A",
                    "Error", "Error", "Error", "Error", "Error", "Error", "Error",
                    "Error", "Error", "Error", "Error"
                ]
            writer.writerow(row_out)

def process_sbom_file(input_file, repo_name, writer): 
    tasks = []
    with open(input_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("package", "").strip()
            version = row.get("version", "").strip()
            package_manager = row.get("language", "").strip().lower()
            license_info = row.get("license", "N/A").strip()

            if package_manager == "golang":
                package_manager = "go"
            if package_manager == "rust":
                package_manager = "cargo"

            if not name or not version or not package_manager:
                print(f"Skipping incomplete row: {row}")
                continue

            print(f"Queueing: {name} {version} ({package_manager})")
            tasks.append((repo_name, name, version, package_manager, license_info))

    process_tasks(tasks, writer)

def add_arguments(parser):  
    g = parser.add_mutually_exclusive_group(required=True)  
    g.add_argument("-a", "--all", action="store_true", help="Use repos from repos.txt")  
    g.add_argument("-r", "--repos", help="Comma-separated repo list, e.g. repo1,repo2")  
    parser.add_argument("--org", default=DEFAULT_ORG, help="GitHub org name (passed to github_sbom)") 
    parser.add_argument("--repos-file", default="repos.txt", help="Path to repos.txt (used with -a)")  
    parser.add_argument("--sbom-dir", default=SBOM_DIR, help="SBOM directory")  
    parser.add_argument("-o", "--output", "--out", dest="output", default=OUTPUT_CSV, help="Output CSV path") 

def parse_cli():  
    p = argparse.ArgumentParser(description="Run bulk health checks from SBOMs.")
    add_arguments(p)  
    return p.parse_args()

def run_bulk(sbom_dir, selected_repos, output_csv):  
    with open(output_csv, "w", newline="", encoding="utf-8") as out_csv:
        writer = csv.writer(out_csv)
        writer.writerow(CSV_HEADER)
        for repo_name, input_file in iter_selected_sboms(sbom_dir, selected_repos):
            print(f"[INFO] Processing {input_file} (repo: {repo_name})")
            process_sbom_file(input_file, repo_name, writer)

def run_bulk_for_repos(repos, sbom_dir=None, output_csv=None, org=DEFAULT_ORG):  
    sbom_dir = sbom_dir or SBOM_DIR  
    output_csv = output_csv or OUTPUT_CSV  
    write_repos_file(sbom_dir, repos, REPOS_FILE_NAME)  
    if not run_github_sbom_script(sbom_dir, org, REPOS_FILE_NAME):  
        print("[WARN] SBOM generation failed; aborting.")  
        return
    run_bulk(sbom_dir, repos, output_csv) 


def main(args=None):
    if args is None:                       
        args = parse_cli() 
           
    if args.all:
        selected_repos = load_repos_from_file(args.repos_file)
    else:
        selected_repos = [r.strip() for r in args.repos.split(",") if r.strip()]

    if not selected_repos:
        print("[ERROR] No repositories selected.")
        return

    write_repos_file(args.sbom_dir, selected_repos, REPOS_FILE_NAME)
    
    if not run_github_sbom_script(args.sbom_dir, args.org, REPOS_FILE_NAME): 
        print("[WARN] SBOM generation failed; aborting.")
        cleanup_sbom_dir(args.sbom_dir)
        return

    try:
        run_bulk(args.sbom_dir, selected_repos, args.output)
        print(f"[INFO] Done. Results saved to {args.output}")
    finally:
        cleanup_sbom_dir(args.sbom_dir)

def cli(args=None):
    return main(args)

if __name__ == "__main__":
    main()
