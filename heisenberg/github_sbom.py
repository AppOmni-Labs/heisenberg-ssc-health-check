# heisenberg/github_sbom.py

import argparse
import requests
import csv
import os

from .config import Settings


_settings = Settings()

DEFAULT_ORG = _settings.org


def clean_package_name(package_name):
    last_nm_idx = package_name.rfind("node_modules/")
    if last_nm_idx != -1:
        package_name = package_name[last_nm_idx + len("node_modules/"):]
    return package_name


def add_arguments(parser):  
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-a", "--all", action="store_true", help="Use repos from repos.txt in working directory")  
    g.add_argument("-r", "--repos", help="Comma-separated repo list") 
    parser.add_argument("-org", "--org", default=DEFAULT_ORG, help="GitHub org name") 
    parser.add_argument("-in", "--repos-file", default="repos.txt", help="Path to repos.txt (used with -a)") 
    parser.add_argument("-out", "--out", default=".", help="Output directory for *_sbom.csv")

# keeping for standalone CLI
def parse_args():
    p = argparse.ArgumentParser(description="Generate SBOM CSVs from GitHub repos")  
    add_arguments(p)  
    return p.parse_args() 

def cli(args=None): 
    if args is None: 
        args = parse_args() 

    org = args.org  
    repos = []  
    if args.all:  
        with open(args.repos_file, "r") as f:
            repos = [line.strip() for line in f if line.strip()]
    else: 
        repos = [r.strip() for r in args.repos.split(",") if r.strip()]

    github_token = os.getenv("GITHUB_TOKEN")
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    os.makedirs(args.out, exist_ok=True) 
    
    for repo in repos:
        print(f"[INFO] Working with repository: {repo}")
        url = f"https://api.github.com/repos/{org}/{repo}/dependency-graph/sbom"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Error fetching SBOM: {response.status_code}\n{response.text}")
            continue

        sbom = response.json()
        packages = sbom.get("sbom", {}).get("packages", [])

        out_path = os.path.join(args.out, f"{repo}_sbom.csv")
        with open(out_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["package", "version", "language", "license"])
            for pkg in packages:
                name = pkg.get("name", "")
                name = clean_package_name(name)
                version = pkg.get("versionInfo", "")
                language = ""
                for ref in pkg.get("externalRefs", []):
                    if ref.get("referenceType") == "purl":
                        locator = ref.get("referenceLocator", "")
                        if locator.startswith("pkg"):
                            language = locator.split(":")[1].split("/")[0]
                        break
                
                license_info = pkg.get("licenseConcluded", "")
                if not license_info or license_info == "NOASSERTION":
                    license_info = pkg.get("licenseDeclared", "")
                if not license_info or license_info == "NOASSERTION":
                    license_info = "N/A"
                
                writer.writerow([name, version, language, license_info])

        print(f"[INFO] Saved SBOM to {out_path}\n")

if __name__ == "__main__": 
    cli()
