#!/usr/bin/env python3

import argparse
import json
import sys
import signal
import os

# Try importing Rich for a better UI, otherwise exit
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import track
    console = Console()
except ImportError:
    print("Error: The 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

# Python Version Check (Modern approach)
if sys.version_info < (3, 6): # 3.4 is too old, set baseline to 3.6+
    console.print("[bold red]Error:[/bold red] XSStrike requires Python 3.6 or higher.")
    sys.exit(1)

# Local imports (Kept original structure)
try:
    from core.config import blindPayload, headers, timeout, threadCount, delay
    from core.encoders import base64
    from core.photon import photon
    from core.prompt import prompt
    from core.updater import updater
    from core.utils import converter, extractHeaders, reader, find_db_file
    from modes.bruteforcer import bruteforcer
    from modes.crawl import crawl
    from modes.scan import scan
    from modes.singleFuzz import singleFuzz
    import core.config
    import core.log
except ImportError as e:
    console.print(f"[bold red]Import Error:[/bold red] Failed to load core modules. \nDetails: {e}")
    sys.exit(1)

# External Dependencies Check
try:
    import concurrent.futures
    from urllib.parse import urlparse
    import fuzzywuzzy
except ImportError as e:
    console.print(f"[bold red]Missing dependency:[/bold red] {e.name}")
    console.print(f"[yellow]Please run:[/yellow] pip3 install -r requirements.txt")
    sys.exit(1) # Exit with error (1)

def show_banner():
    """Displays the banner using Rich"""
    banner_text = """
    XSStrike v3.1.7
    Advanced XSS Detection Suite
    """
    console.print(Panel(banner_text, style="bold red", subtitle="Refactored Version"))

def setup_args():
    """Sets up argparse"""
    parser = argparse.ArgumentParser(
        description="XSStrike Advanced XSS Scanner",
        epilog="""
Examples:
  # Basic scan
  python xsstrike.py -u "http://example.com/page?param=value"
  
  # Fuzzer mode
  python xsstrike.py --fuzzer -u "http://example.com/page?param=value"
  
  # POST request with data
  python xsstrike.py -u "http://example.com/login" --data "username=test&password=test"
  
  # Crawl mode
  python xsstrike.py --crawl -u "http://example.com" -l 3
  
  # With custom payloads file
  python xsstrike.py -u "http://example.com/page?param=value" -f payloads.txt
  
  # With encoding
  python xsstrike.py -u "http://example.com/page?param=value" -e base64
  
  # With delay and timeout
  python xsstrike.py -u "http://example.com/page?param=value" -d 2 --timeout 10
  
  # JSON POST data
  python xsstrike.py -u "http://example.com/api" --data '{"key":"value"}' --json
  
  # With custom headers
  python xsstrike.py -u "http://example.com/page?param=value" --headers "Cookie: session=abc123"
  
  # Blind XSS
  python xsstrike.py --crawl -u "http://example.com" --blind
  
  # Multiple threads
  python xsstrike.py --crawl -u "http://example.com" -t 10
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main arguments
    parser.add_argument('-u', '--url', help='Target URL (e.g., http://example.com/page?param=value)', dest='target')
    parser.add_argument('--data', help='POST data (e.g., param1=value1&param2=value2)', dest='paramData')
    parser.add_argument('-e', '--encode', help='Encode payloads (e.g., base64)', dest='encode')
    parser.add_argument('--fuzzer', help='Fuzzer mode - test fuzzing strings on parameters', dest='fuzz', action='store_true')
    parser.add_argument('--update', help='Update XSStrike', dest='update', action='store_true')
    
    # Execution settings
    parser.add_argument('--timeout', help='Timeout in seconds (default: from config)', dest='timeout', type=int, default=core.config.timeout)
    parser.add_argument('--proxy', help='Use proxy', dest='proxy', action='store_true')
    parser.add_argument('--crawl', help='Crawl mode - crawl and test all forms/URLs found', dest='recursive', action='store_true')
    parser.add_argument('--json', help='Treat POST data as JSON', dest='jsonData', action='store_true')
    parser.add_argument('--path', help='Inject payloads in the path instead of parameters', dest='path', action='store_true')
    
    # Files and Logs
    parser.add_argument('--seeds', help='Load crawling seeds from file (e.g., seeds.txt)', dest='args_seeds')
    parser.add_argument('-f', '--file', help='Load payloads from file (e.g., payloads.txt)', dest='args_file')
    parser.add_argument('-l', '--level', help='Crawl level depth (default: 2)', dest='level', type=int, default=2)
    parser.add_argument('--headers', help='Add custom headers (e.g., "Cookie: session=abc" or use without value for interactive prompt)', dest='add_headers', nargs='?', const=True)
    parser.add_argument('-t', '--threads', help='Number of threads (default: from config)', dest='threadCount', type=int, default=core.config.threadCount)
    parser.add_argument('-d', '--delay', help='Delay between requests in seconds (default: from config)', dest='delay', type=int, default=core.config.delay)
    
    # Boolean Flags
    parser.add_argument('--skip', help='Don\'t ask to continue scanning', dest='skip', action='store_true')
    parser.add_argument('--skip-dom', help='Skip DOM checking', dest='skipDOM', action='store_true')
    parser.add_argument('--blind', help='Inject blind XSS payload', dest='blindXSS', action='store_true')
    
    # Logging
    parser.add_argument('--console-log-level', help='Console logging level', dest='console_log_level', 
                        default=core.log.console_log_level, choices=core.log.log_config.keys())
    parser.add_argument('--file-log-level', help='File logging level', dest='file_log_level',
                        choices=core.log.log_config.keys(), default=None)
    parser.add_argument('--log-file', help='Log file name', dest='log_file', default=core.log.log_file)
    
    return parser.parse_args()

def handle_sigint(signal, frame):
    """Handles Ctrl+C for a clean exit"""
    console.print("\n[bold yellow]Aborted by user.[/bold yellow]")
    sys.exit(0)

def main():
    # Register Ctrl+C signal
    signal.signal(signal.SIGINT, handle_sigint)

    # Initial Setup
    show_banner()
    args = setup_args()

    # Log Configuration
    core.log.console_log_level = args.console_log_level
    core.log.file_log_level = args.file_log_level
    core.log.log_file = args.log_file
    logger = core.log.setup_logger()

    # Mapping args to global config (Required for XSStrike internals)
    core.config.globalVariables = vars(args)

    # Headers Logic
    current_headers = core.config.headers # Default
    if isinstance(args.add_headers, bool):
        current_headers = extractHeaders(prompt())
    elif isinstance(args.add_headers, str):
        current_headers = extractHeaders(args.add_headers)
    
    core.config.globalVariables['headers'] = current_headers
    core.config.globalVariables['checkedScripts'] = set()
    core.config.globalVariables['checkedForms'] = {}
    
    # Loading DB definitions
    definitions_file = find_db_file('definitions.json')
    try:
        if definitions_file:
            with open(definitions_file, 'r') as db_file:
                core.config.globalVariables['definitions'] = json.load(db_file)
        else:
            raise FileNotFoundError("db/definitions.json not found")
    except FileNotFoundError:
        console.print("[bold red]Critical Error:[/bold red] db/definitions.json not found.")
        sys.exit(1)

    # Update Logic
    if args.update:
        updater()
        sys.exit(0)

    # Check if target is specified
    if not args.target and not args.args_seeds:
        console.print("[yellow]No target specified.[/yellow] Use -h for help.")
        sys.exit(1) # User input error is an error (1)

    # Data Processing (ParamData)
    local_param_data = args.paramData
    if args.path:
        local_param_data = converter(args.target, args.target)
    elif args.jsonData:
        current_headers['Content-type'] = 'application/json'
        local_param_data = converter(local_param_data)

    # Payloads
    payloadList = core.config.payloads
    if args.args_file:
        if args.args_file != 'default':
            payloadList = list(filter(None, reader(args.args_file)))

    # Seeds
    seedList = []
    if args.args_seeds:
        seedList = list(filter(None, reader(args.args_seeds)))

    # Encoding
    encoding = base64 if args.encode and args.encode == 'base64' else False
    
    if not args.proxy:
        core.config.proxies = {}

    # --- MAIN EXECUTION FLOW ---

    if args.fuzz:
        singleFuzz(args.target, local_param_data, encoding, current_headers, args.delay, args.timeout)
    
    elif not args.recursive and not args.args_seeds:
        if args.args_file:
            bruteforcer(args.target, local_param_data, payloadList, encoding, current_headers, args.delay, args.timeout)
        else:
            scan(args.target, local_param_data, encoding, current_headers, args.delay, args.timeout, args.skipDOM, args.skip)
    
    else:
        # Crawler Mode
        if args.target:
            seedList.append(args.target)
        
        for target_url in seedList:
            logger.run(f'Crawling target: {target_url}')
            parsed = urlparse(target_url)
            scheme = parsed.scheme
            host = parsed.netloc
            main_url = f"{scheme}://{host}"
            
            # Photon Crawler
            crawlingResult = photon(target_url, current_headers, args.level, 
                                  args.threadCount, args.delay, args.timeout, args.skipDOM)
            
            forms = crawlingResult[0]
            domURLs = list(crawlingResult[1])
            
            # List normalization for zip function
            difference = abs(len(domURLs) - len(forms))
            if len(domURLs) > len(forms):
                forms.extend([0] * difference)
            elif len(forms) > len(domURLs):
                domURLs.extend([0] * difference)
            
            # Concurrent Execution
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threadCount) as executor:
                futures = []
                for form, domURL in zip(forms, domURLs):
                    futures.append(executor.submit(
                        crawl, scheme, host, main_url, form, 
                        args.blindXSS, blindPayload, current_headers, 
                        args.delay, args.timeout, encoding
                    ))
                
                # Simplified Progress Bar
                completed = 0
                total = len(forms)
                for _ in concurrent.futures.as_completed(futures):
                    completed += 1
                    if completed == total or completed % args.threadCount == 0:
                        logger.info(f'Progress: {completed}/{total}\r')
            
            logger.no_format('')

if __name__ == "__main__":
    main()