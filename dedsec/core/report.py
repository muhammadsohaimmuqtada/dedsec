import json
from datetime import datetime
from dedsec.core.colors import Colors

def generate_report(url, domain, results, json_output=False, output_file=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}  DEDSEC SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Target:    {url}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Domain:    {domain}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Timestamp: {timestamp}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Modules:   {len(results)} completed")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    if json_output or output_file:
        report_data = {
            "url": url,
            "domain": domain,
            "timestamp": timestamp,
            "results": results
        }
        if json_output:
            print(json.dumps(report_data, indent=2, default=str))
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            print(f"{Colors.GREEN}[+]{Colors.RESET} Report saved to: {output_file}")
