from models import Report

def print_human_report(report: Report):
    from textwrap import shorten
    print_logo()
    print(f"Target: {report.target}")
    print(f"Timestamp (UTC): {report.timestamp_utc}")
    print("\nMetadata:")
    for k,v in report.metadata.items():
        print(f"  - {k}: {v}")
    print("\nFindings (grouped by severity):")
    order = ['high','medium','low','info']
    for sev in order:
        items = [f for f in report.findings if f.severity == sev]
        if not items:
            continue
        print(f"\n  {sev.upper()} ({len(items)}):")
        for f in items:
            desc = shorten(f.description, width=100, placeholder='…')
            ev = f" [evidence: {f.evidence}]" if f.evidence else ''
            print(f"    - {f.category}: {f.name}{ev}")
            print(f"        Desc: {desc}")
            if f.mitigation:
                print(f"        Mitigation: {f.mitigation}")
            if f.references:
                print(f"        References:")
                for r in f.references:
                    print(f"          * {r}")
    print("\nSummary counts:")
    for sev,count in report.summary.items():
        print(f"  {sev}: {count}")


def print_logo():
    logo_ascii = r"""
__        ______  ____                      
\ \      / /  _ \|  _ \ ___  ___ ___  _ __  
 \ \ /\ / /| |_) | |_) / _ \/ __/ _ \| '_ \ 
  \ V  V / |  __/|  _ <  __/ (_| (_) | | | |
   \_/\_/  |_|   |_| \_\___|\___\___/|_| |_|

        Passive WordPress Security Scanner
            Created by Mart Salazar
    """
    print(logo_ascii)