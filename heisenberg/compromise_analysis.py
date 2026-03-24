# heisenberg/compromise_analysis.py

import csv
import os
import sys
import argparse

from .config import Settings 
_settings = Settings()
DEFAULT_OUTPUT = getattr(_settings, "output_csv", "analyze_matches.csv")

from .sbom_utils import (
    write_repos_file, load_repos_from_file,
    run_github_sbom_script, iter_selected_sboms,
    cleanup_sbom_dir
)

def _read_list_file(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out

def _split_csv_list(s):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def _normalize(s, case_sensitive):
    s = (s or "").strip()
    return s if case_sensitive else s.lower()

def _dedupe_rows_preserve_order(rows):
    seen = set()
    out = []
    for r in rows:
        key = tuple(r)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

def _load_header_and_rows(sbom_csv, match_column="package"):
    if not os.path.exists(sbom_csv):
        raise FileNotFoundError(f"SBOM not found: {sbom_csv}")
    with open(sbom_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        if match_column not in header:
            raise ValueError(f"SBOM CSV is missing required '{match_column}' column.")
        rows = list(reader)
    return header, rows


def run_analyze(sbom_csv, targets, case_sensitive, match_column="package"):
    print(f"[INFO] Loading SBOM: {sbom_csv}")
    header, rows = _load_header_and_rows(sbom_csv, match_column=match_column)

    print(f"[INFO] Matching {len(targets)} targeta against column '{match_column}'")
    wanted = { _normalize(x, case_sensitive) for x in targets if x.strip() }

    matches = []
    for row in rows:
        pkg = row.get(match_column, "")
        if _normalize(pkg, case_sensitive) in wanted:
            matches.append([row.get(col, "") for col in header])

    matches = _dedupe_rows_preserve_order(matches)
    print(f"[INFO] Found {len(matches)} matching row(s)")
    return header, matches


def add_arguments(parser):
    target = parser.add_mutually_exclusive_group(required=True)  
    target.add_argument("-sbom", "--sbom", help="Path to SBOM CSV to scan.")  
    target.add_argument("-r", "--repos", help="Comma-separated repo list, e.g. 'repo1,repo2'.")  
    target.add_argument("-a", "--all", action="store_true",
                        help="Use repos from repos.txt (requires --org/--repos-file).")  
    
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-pkg", "--pkg", help="Comma-separated package names, e.g. 'pkg1,pkg2'.")
    g.add_argument("-file", "--file", help="Text file of package names (one per line).")

    parser.add_argument("-o", "--output", "--out", dest="output", default=DEFAULT_OUTPUT,
                        help=f"Output CSV path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--case-sensitive", action="store_true",
                        help="Match package names case-sensitively (default: case-insensitive).")
    parser.add_argument("--column", default="package",
                        help="CSV column to match against (default: 'package'). Use 'full_action' for actions investigations.")
    parser.add_argument("--org", default=_settings.org,
                        help="GitHub org name (used when -r/--repos or -a/--all is provided).")
    parser.add_argument("--repos-file", default=_settings.repos_file_name,
                        help="Path to repos.txt (used with -a/--all).")
    parser.add_argument("--sbom-dir", default=_settings.sbom_dir,
                        help="Directory to write/read SBOM CSVs when using repo mode.")

def parse_cli():
    p = argparse.ArgumentParser(description="Analyze SBOM CSV for presence of specific package names.")
    add_arguments(p)
    return p.parse_args()

def _analyze_single(sbom_csv, targets, case_sensitive, writer, wrote_header: list[bool], repo_name: str | None = None):
    header, rows = run_analyze(sbom_csv, targets, case_sensitive)
    if repo_name:
        if not wrote_header[0]:
            writer.writerow(["repo_name"] + header)  
            wrote_header[0] = True
        for r in rows:
            writer.writerow([repo_name] + r)
    else:
        if not wrote_header[0]:
            writer.writerow(header)
            wrote_header[0] = True
        writer.writerows(rows)

def main(args=None):
    if args is None:
        args = parse_cli()

    targets = []
    if getattr(args, "pkg", None):
        targets.extend(_split_csv_list(args.pkg))
    if getattr(args, "file", None):
        targets.extend(_read_list_file(args.file))

    if not targets:
        print("[ERROR] No package names provided.")
        return 2
    
    if getattr(args, "sbom", None):
        try:
            header, rows = run_analyze(args.sbom, targets, args.case_sensitive, match_column=args.column)
        except Exception as e:
            print(f"[ERROR] {e}")
            return 1

        try:
            out_path = args.output
            if out_path == "-":
                writer = csv.writer(sys.stdout)
                writer.writerow(header)
                writer.writerows(rows)
                print("[INFO] Wrote matches to stdout", file=sys.stderr)
            else:
                with open(out_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(header)
                    writer.writerows(rows)
                print(f"[INFO] Done. Results saved to {out_path}")
        except Exception as e:
            print(f"[ERROR] Failed to write output: {e}")
            return 1
        return 0
    
    if args.all:
        selected_repos = load_repos_from_file(args.repos_file)
    else:
        selected_repos = [r.strip() for r in (args.repos or "").split(",") if r.strip()]
    
    if not selected_repos:
        print("[ERROR] No repositories selected.")
        return 2
    
    write_repos_file(args.sbom_dir, selected_repos, _settings.repos_file_name)
    if not run_github_sbom_script(args.sbom_dir, args.org, _settings.repos_file_name):
        print("[WARN] SBOM generation failed; aborting.")
        return 1

    try:
        if args.output == "-":
            out_writer = csv.writer(sys.stdout)
            wrote_header = [False]
            for repo_name, sbom_path in iter_selected_sboms(args.sbom_dir, selected_repos):
                print(f"[INFO] Analyzing {sbom_path} (repo: {repo_name})", file=sys.stderr)  
                _analyze_single(sbom_path, targets, args.case_sensitive, out_writer, wrote_header, repo_name=repo_name)
            print("[INFO] Wrote matches to stdout", file=sys.stderr)
        else:
            with open(args.output, "w", encoding="utf-8", newline="") as f:
                out_writer = csv.writer(f)
                wrote_header = [False]
                for repo_name, sbom_path in iter_selected_sboms(args.sbom_dir, selected_repos):
                    print(f"[INFO] Analyzing {sbom_path} (repo: {repo_name})")
                    _analyze_single(sbom_path, targets, args.case_sensitive, out_writer, wrote_header, repo_name=repo_name)
            print(f"[INFO] Done. Results saved to {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to write output: {e}")
        return 1
    finally:
        cleanup_sbom_dir(args.sbom_dir)
    
    return 0

def cli(args=None):
    return main(args)

if __name__ == "__main__":
    sys.exit(main())
