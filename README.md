<p align="center">
  <img src="img/breaking-bad.png" width="300" alt="Heisenberg diagram">
</p>

# Heisenberg - Software Supply Chain Se[pu]rity
Heisenberg is a software supply chain health check tool that analyzes dependencies using deps.dev, SBOMs, and external advisories. It helps measure package health, detect potential risks, and generate reports for individual dependencies or in bulk.

## Features
-   `heisenberg check` - Inspect a single package@version (npm, PyPI, Go)
-   `heisenberg bulk` - Generate SBOMs for one or more repos or list of repos from the file, then parallel-check all dependencies and writes a CSV report. Also supports **vendor SBOM assessment** (CycloneDX, SPDX, CSV formats) in `vendor` mode.
-   `heisenberg sbom` - Generate SBOMs for one or more repos [in case you need one].
-   `heisenberg actions` - Assess GitHub Actions supply chain health across repos. Detects unpinned actions, fetches repo metadata and security advisories, and resolves internal shared actions to their real third-party dependencies. Supports incident response filtering (`-pkg`, `-file`) to instantly find which repos use a specific action.
-   Adds **Custom Health Score** (experimental) that blends popularity, maintenance, vulnerabilities, and dependents (weighing heavier into security).
-   CSV includes cross-check URLs (deps.dev / Snyk / Socket).

## Quick Start
```bash
# 1. Set up your GitHub token
export GITHUB_TOKEN=ghp_YOUR_TOKEN
export GITHUB_ORG=your-github-org

# 2. Install with pipx [if you don't want to install keep reading]
pipx install "git+https://github.com/AppOmni-Labs/heisenberg-ssc-health-check"

# 3. Check a single package
heisenberg check -mgmt npm -pkg lodash -v 4.17.21

# 4. Generate bulk report for your repos
heisenberg bulk -r repo1,repo2 -o results.csv

# 5. Assess vendor SBOM
heisenberg vendor --sbom-file vendor.cdx.json -o vendor_report.csv

# 6. Analyze repos for presence of affected packages
heisenberg analyze -r repo1,repo2 -pkg chalk,debug

# 7. Assess GitHub Actions supply chain health
heisenberg actions -r repo1,repo2 -o actions_report.csv

# 8. Incident response — find which repos use a specific GHA
heisenberg actions -a --repos-file repos.txt -pkg aquasecurity/trivy-action@0.30.0 -o gha_hits.csv
```

## Installation
For Heisenberg to do its work efficiently, it needs to be able to pull your repos SBOM. To do that you have to get GitHub token `repo:read` permissions and export it. 
```
export GITHUB_TOKEN=ghp_YOUR_TOKEN
```
Heisenberg requires python 3.11. 

If you would like to install you can do the following:
```
# Install with pipx
pipx install "git+https://github.com/AppOmni-Labs/heisenberg-ssc-health-check"
export GITHUB_ORG=your-github-org                       # this needed so you don't need to supply github org in every command

# From source
git clone https://github.com/AppOmni-Labs/heisenberg-ssc-health-check

# You have the choice to export GITHUB_ORG as above export GITHUB_ORG=your-github-org
# Or you can set org manually in the config before installing
# Or if none of that works for you, you can supply org manually in the command using --org

cd heisenberg-ssc-health-check
# open heisenberg/config.py and find this line - org: str = os.getenv("GITHUB_ORG", "")
# change it to - org: str = os.getenv("GITHUB_ORG", "my-github-org") and save. Then run install.

pip install -e .
```
If you do not wish to install the tool you can just clone it and run it directly with python
```
git clone https://github.com/AppOmni-Labs/heisenberg-ssc-health-check
cd heisenberg-ssc-health-check

# Run the CLI via modules:
python -m heisenberg.main sbom -r my_repo
python -m heisenberg.main check -mgmt pypi -pkg requests -v 2.32.3
python -m heisenberg.main bulk -r repo1,repo2 --org your-org --sbom-dir sbom_tmp -o results.csv
python -m heisenberg.main analyze -r repo1,repo2 --org your-org -pkg left-pad -o findings.csv
```

## Usage
CLI's 5 separate modes:
```
usage: heisenberg [-h] {sbom,check,bulk,vendor,analyze,actions} ...

Heisenberg toolkit

positional arguments:
  {sbom,check,bulk,vendor,analyze,actions}
    sbom                Generate SBOMs from GitHub repos
    check               Check a single package via deps.dev
    bulk                Run bulk health checks over repos
    vendor              Assess vendor/third-party SBOM
    analyze             Find and return compromised packages in an SBOM
    actions             Check GitHub Actions supply chain health

options:
  -h, --help            show this help message and exit
```

### SBOM Mode
SBOM is the most basic mode. It is used by bulk behind the scenes to generate report for one or multiple repos. However, it can be used on its own and could be useful during investigations coupled with `analyze` mode (discussed below). 

```
usage: heisenberg sbom [-h] (-a | -r REPOS) [-org ORG] [-in REPOS_FILE] [-out OUT]

options:
  -h, --help            show this help message and exit
  -a, --all             Use repos from repos.txt in working directory
  -r REPOS, --repos REPOS
                        Comma-separated repo list
  -org ORG, --org ORG   GitHub org name [OPTIONAL IF DEFAULT ORG WAS SET]
  -in REPOS_FILE, --repos-file REPOS_FILE
                        Path to repos.txt (used with -a)
  -out OUT, --out OUT   Output directory for *_sbom.csv [OPTIONAL]
```
#### Examples
```
# Generate SBOM for a single repo - my_repo. Will generate my_repo_sbom.csv
heisenberg sbom -r my_repo 

# Generate SBOM for a couple of repos - my_repo1, my_repo2 and store it in my_repos_sbom directory.
heisenberg sbom -r my_repo1, my_repo2 -out my_repos_sbom 

# Generate SBOM for multiple repos from repos.txt file where repo is listed on its separate line and store it in repos_sbom directory.
heisenberg sbom -a -out repos_sbom
```

### Check Mode
Inspect a single package@version (npm, PyPI, Go) and print a human-readable report to stdout.
```
usage: heisenberg check [-h] -mgmt MGMT -pkg PKG -v VERSION [{main_package}]

positional arguments:
  {main_package}        Only 'main_package' is supported.

options:
  -h, --help                     show this help message and exit
  -mgmt MGMT, --mgmt MGMT        Package management system (e.g., pypi or npm)
  -pkg PKG, --pkg PKG            Package name
  -v VERSION, --version VERSION  Package version
```
#### Examples
```
# PyPI
heisenberg check -mgmt pypi -pkg requests -v 2.32.3

# npm
heisenberg check -mgmt npm -pkg lodash -v 4.17.21

# Go
heisenberg check -mgmt go -pkg github.com/spf13/cobra -v v1.8.1
```
#### Example of what you will see
```
walter-white 💀 heisenberg [main] -> heisenberg check -mgmt npm -pkg lodash -v 4.17.21 
Package: lodash
Version: 4.17.21
Package Health Score: 4.2
Description: A modern JavaScript utility library delivering modularity, performance, & extras.
Popularity (Stars): 61137
Popularity (Forks): 7080
Dependents: 702873
Maintained Score: 0
Security Advisory: None
Deprecated: None
Custom Health Score: 4.6
Security Score (Vulnerabilities): 0
Published At: 2021-02-20T15:42:16Z
Fresh Publish (<24h): No
Has Postinstall: No
Lifecycle Scripts: None
```

### Bulk Mode
This mode create health check report for your supply chain - selected repos or an entire github protfolio. Generates SBOMs for all or selected repos, then parallel-check every dependency and write a single CSV report. SBOMs are auto-cleaned after the report is produced.
```
usage: heisenberg bulk [-h] (-a | -r REPOS) [--org ORG] [--repos-file REPOS_FILE] [--sbom-dir SBOM_DIR] [-o OUTPUT]

options:
  -h, --help                show this help message and exit
  -a, --all                 Use repos from repos.txt
  -r REPOS, --repos REPOS   Comma-separated repo list, e.g. repo1,repo2
  --org ORG                 GitHub org name (uses DEFAULT that is set in config)
  --repos-file REPOS_FILE   Path to repos.txt (used with -a)
  --sbom-dir SBOM_DIR       SBOM directory
  -o OUTPUT, --out OUTPUT   Output CSV path
```
#### Examples:
```
# Individual inline repos
heisenberg bulk -r repo1,repo2 -o results.csv [set --org ORG if you haven't set DEFAULT]

# Multiple repos from repos.txt
heisenberg bulk --all --repos-file repos.txt -o results.csv
```
#### Output CSV report columns
```repo_name, package, version, language, license, health_score, custom_health_score, description, popularity_info_stars, popularity_info_forks, maintenance_info, dependents, security_info, security_advisories, security_score, deprecated, deps_url, snyk_url, socket_url```


### Vendor Mode
Assess vendor/third-party SBOMs for supply chain risk. Accepts SBOM files in **CycloneDX** (JSON/XML), **SPDX** (JSON/XML), or **CSV** format and generates a comprehensive health report.

```
usage: heisenberg vendor [-h] --sbom-file SBOM_FILE [-o OUTPUT] [--vendor-name VENDOR_NAME]

options:
  -h, --help                     show this help message and exit
  --sbom-file SBOM_FILE          Path to vendor SBOM file (CycloneDX/SPDX/CSV)
  -o OUTPUT, --out OUTPUT        Output CSV path
  --vendor-name VENDOR_NAME      Optional vendor name (used as repo_name in output)
```

#### Examples:
```
# Assess CycloneDX SBOM
heisenberg vendor --sbom-file vendor.cdx.json -o vendor_assessment.csv

# Assess SPDX XML SBOM with custom vendor name
heisenberg vendor --sbom-file acme-corp.spdx.xml --vendor-name "ACME Corp" -o acme_report.csv

# Assess CSV SBOM
heisenberg vendor --sbom-file third-party.csv -o third_party_report.csv
```

**Supported SBOM Formats:**
- CycloneDX: JSON (`.json`, `.cdx`) and XML (`.xml`)
- SPDX: JSON (`.json`) and XML (`.xml`)
- CSV: GitHub SBOM style

#### Output CSV report columns
```repo_name, package, version, language, license, health_score, custom_health_score, description, popularity_info_stars, popularity_info_forks, maintenance_info, dependents, security_info, security_advisories, security_score, deprecated, deps_url, snyk_url, socket_url```

### Analyze Mode
This is an investigation mode that searches SBOM(s) for the presence of specific package names (case-insensitive by default). You can point at one SBOM file or let the tool generate SBOMs for repos (and it will auto-clean them afterwards). Output is a CSV of the matching rows from each SBOM.
```
usage: heisenberg analyze [-h] (-sbom SBOM | -r REPOS | -a) (-pkg PKG | -file FILE) [-o OUTPUT] [--case-sensitive] [--org ORG] [--repos-file REPOS_FILE]
                          [--sbom-dir SBOM_DIR]

options:
  -h, --help                show this help message and exit
  -sbom SBOM, --sbom SBOM   Path to SBOM CSV to scan.
  -r REPOS, --repos REPOS   Comma-separated repo list, e.g. 'repo1,repo2'.
  -a, --all                 Use repos from repos.txt (requires --org/--repos-file).
  -pkg PKG, --pkg PKG       Comma-separated package names, e.g. 'pkg1,pkg2'.
  -file FILE, --file FILE   Text file of package names (one per line).
  -o OUTPUT, --out OUTPUT   Output CSV path (default: repos_sbom_results.csv)
  --case-sensitive          Match package names case-sensitively (default: case-insensitive).
  --org ORG                 GitHub org name (used when -r/--repos or -a/--all is provided).
  --repos-file REPOS_FILE   Path to repos.txt (used with -a/--all).
  --sbom-dir SBOM_DIR       Directory to write/read SBOM CSVs when using repo mode.
```
#### Examples
```
# Locate chalk and debug packages across a few repos
heisenberg analyze -r repo1,repo2 -pkg chalk,debug

# Locate chalk and debug packages across multiple repos
heisenberg analyze -a repos.txt -pkg chalk,debug

# Locate chalk and debug packages in the existing SBOM
heisenberg analyze -sbom SBOM -pkg chalk,debug

# Locate 100s of packages affected by Shai Hulud across multiple of the repos
heisenberg analyze -a repos.txt -file affected_pkgs.txt
```
### Example Output
```
walter-white 💀 heisenberg [main] -> heisenberg analyze -r blue_sky -file affected_supply.txt
[INFO] Wrote repo list to sbom/repos.txt
[INFO] Running SBOM generator: python -m heisenberg.github_sbom -a --org heisenberg_empire --repos-file repos.txt -out . (cwd=sbom)
[INFO] Working with repository: blue_sky
[INFO] Saved SBOM to ./blue_sky_sbom.csv

[INFO] Analyzing sbom/blue_sky_sbom.csv (repo: blue_sky)
[INFO] Loading SBOM: sbom/blue_sky_sbom.csv
[INFO] Matching 2 target package name(s)
[INFO] Found 2 matching row(s)
[INFO] Done. Results saved to blue_sky_sbom_sbom_results.csv
[INFO] Cleaned up SBOM directory: sbom
```

### Actions Mode
This mode assess GitHub Actions supply chain health across one or more repos. Fetches workflow files, extracts every `uses:` directive, and enriches each with GitHub repo metadata and security advisories. Automatically resolves internal shared actions (e.g. `YOUR_ORG/.github/actions/perform-trivy-scan@v1.2.3`) to their real third-party dependencies — so risk hidden inside your shared actions repo is surfaced.

Set `HEIS_SHARED_ACTIONS_REPO` to the name of your shared actions repo (default: `.github`).

```
usage: heisenberg actions [-h] (-r REPOS | -a) [--org ORG] [--repos-file REPOS_FILE] [-o OUTPUT] [-pkg PKG | -file FILE]

options:
  -h, --help                  show this help message and exit
  -r REPOS, --repos REPOS     Comma-separated repo list, e.g. repo1,repo2
  -a, --all                   Use repos from --repos-file
  --org ORG                   GitHub org name
  --repos-file REPOS_FILE     Path to repos.txt (used with -a)
  -o OUTPUT, --output OUTPUT  Output CSV path (default: actions_results.csv)
  -pkg PKG, --pkg PKG         Filter output to specific actions, e.g. tj-actions/changed-files
  -file FILE, --file FILE     Text file of action names to filter on (one per line)
```

#### Examples
```
# Full inventory for one repo
heisenberg actions -r myrepo --org myorg -o actions_results.csv

# Full inventory across all repos
heisenberg actions -a --repos-file repos.txt --org myorg -o actions_results.csv

# Incident response — which repos use a specific action?
heisenberg actions -r repo1,repo2,repo3 --org myorg -pkg aquasecurity/trivy-action@0.30.0 -o hits.csv

# Incident response — check against a list of known-bad actions or multiple version of the same action
heisenberg actions -a --repos-file repos.txt --org myorg -file compromised_actions.txt -o hits.csv
```

#### Output CSV columns
```
repo, workflow_file, resolved_via, full_action, owner, action_repo, ref, is_sha_pinned, action_type, stars, forks, archived, disabled, last_push, action_description, advisories, repo_error
```

**What to look for:**
- `is_sha_pinned = False` — action is on a mutable tag, vulnerable to tag-hijack
- `resolved_via` populated — third-party action reached through an internal shared action; risk is inherited by every repo calling it
- `archived = True` — action repo is no longer maintained
- `advisories` — GHSA IDs published on the action's repo

#### Searching an existing actions CSV with `analyze`
If you already have an actions CSV on disk, search it with `analyze` using `--column full_action`:
```
heisenberg analyze -sbom actions_results.csv -pkg aquasecurity/trivy-action@0.30.0 --column full_action
heisenberg analyze -sbom actions_results.csv -file compromised_actions.txt --column full_action
```
---

## Github Action
Heisenberg comes with Github Action for proactive detection. If you wish to try it, follow this link - https://github.com/appomni/test-gha-prodsec

Or you can just add this configuration in your repo under .github/workflows and paste it in something like heisenberg-supply-chain-security.yaml

```
name: Heisenberg Health Check
on:
  pull_request:
    paths:
      - "**/poetry.lock"
      - "**/uv.lock"
      - "**/package-lock.json"
      - "**/yarn.lock"
      - "**/requirements.txt"
      - "**/go.mod"

permissions:
  contents: read
  pull-requests: write   # PR comment
  issues: write          # create label

jobs:
  deps-health:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Detect changed manifest
        id: detect
        run: |
          git fetch origin ${{ github.base_ref }} --depth=1
          LOCK_PATH=$(git diff --name-only origin/${{ github.base_ref }} | \
            grep -E 'poetry.lock$|uv.lock$|package-lock.json$|yarn.lock$|requirements.txt$|go.mod$' | head -n1 || true)
          echo "lock_path=$LOCK_PATH" >> $GITHUB_OUTPUT

      - name: Heisenberg Dependency Health Check
        uses: AppOmni-Labs/heisenberg-ssc-gha@v1
        with:
          package_file: ${{ steps.detect.outputs.lock_path }}
```
