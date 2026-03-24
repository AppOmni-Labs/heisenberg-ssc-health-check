# heisenberg/main.py

import argparse
from . import github_sbom, heisenberg_depsdev, bulk_check, compromise_analysis, vendor, actions_bulk 


def cli():
    p = argparse.ArgumentParser(prog="heisenberg", description="Heisenberg toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    sbom_parser = sub.add_parser("sbom", help="Generate SBOMs from GitHub repos")
    github_sbom.add_arguments(sbom_parser)

    check_parser = sub.add_parser("check", help="Check a single package via deps.dev")
    heisenberg_depsdev.add_arguments(check_parser)

    bulk_parser = sub.add_parser("bulk", help="Run bulk health checks over repos")
    bulk_check.add_arguments(bulk_parser)

    vendor_parser = sub.add_parser("vendor", help="Assess vendor/third-party SBOM")
    vendor.add_arguments(vendor_parser)

    analyze_parser = sub.add_parser("analyze", help="Find and return compromised packages in an SBOM")
    compromise_analysis.add_arguments(analyze_parser)

    actions_parser = sub.add_parser("actions", help="Check GitHub Actions supply chain health")
    actions_bulk.add_arguments(actions_parser)       

    args = p.parse_args()

    
    if args.cmd == "sbom":
        github_sbom.cli(args)
    elif args.cmd == "check":
        heisenberg_depsdev.cli(args)
    elif args.cmd == "bulk":
        bulk_check.cli(args)
    elif args.cmd == "vendor":
        vendor.cli(args)
    elif args.cmd == "analyze":
        compromise_analysis.cli(args)
    elif args.cmd == "actions":
        actions_bulk.cli(args)

if __name__ == "__main__":
    cli()
