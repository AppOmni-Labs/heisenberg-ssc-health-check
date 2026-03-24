# heisenberg/config.py

import os

class Settings: 
    org: str = os.getenv("GITHUB_ORG", "")  
    sbom_dir: str = os.getenv("HEIS_SBOM_DIR", "sbom")  
    output_csv: str = os.getenv("HEIS_OUTPUT", "repos_sbom_results.csv") 
    shared_actions_repo: str = os.getenv("HEIS_SHARED_ACTIONS_REPO", ".github")

    deps_script: str = os.getenv("HEIS_DEPS_SCRIPT", "heisenberg_depsdev.py")  

    timeout: int = int(os.getenv("HEIS_TIMEOUT", "30"))  
    max_workers: int = int(os.getenv("HEIS_MAX_WORKERS", "4"))  
    pause_every: int = int(os.getenv("HEIS_PAUSE_EVERY", "20"))  
    pause: float = float(os.getenv("HEIS_PAUSE_SECS", "0.5")) 

    repos_file_name: str = os.getenv("HEIS_REPOS_FILE", "repos.txt") 
