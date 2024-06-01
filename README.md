# Headres
Python script for performing header injection testing. This script uses a list of global headers and injection payloads to test for potential vulnerabilities in a given URL. Here's a breakdown of how the script works:

# Global Headers and Injection Payloads:

+ The global_headers list contains a wide range of HTTP headers that are commonly used in web requests.
+ The inject list includes various payloads that can be used for header injection testing, such as SQL injection, XSS, and other malicious inputs.

# Functions:

1. resolve_content_length(url, headers, method):
This function sends a request to the specified URL with custom headers and method (GET or POST) to determine the content length of the response.
It returns the content length or None if the request fails.

2. header_inject(url, methods, verbose):
This function iterates over HTTP methods (GET, POST) and global headers to inject different payloads and compare the content length of responses.
It prints out potential successful injections based on changes in content length.

# Main Functionality:

+ The main() function parses command-line arguments using argparse to specify the URL, HTTP methods, and verbosity.
+ It validates the URL and then calls the header_inject() function to perform the header injection testing.
+ The script handles interruptions gracefully and provides colored output using colorama.

# Installation
```
https://github.com/XJOKZVO/Headres
```

# Options:
```
 _   _                      _                     
| | | |   ___    __ _    __| |   ___   _ __   ___ 
| |_| |  / _ \  / _` |  / _` |  / _ \ | '__| / __|
|  _  | |  __/ | (_| | | (_| | |  __/ | |    \__ \
|_| |_|  \___|  \__,_|  \__,_|  \___| |_|    |___/

usage: Headres.py [-h] -u URL [-m METHODS [METHODS ...]] [-v]

Perform header injection testing.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to test for header injection
  -m METHODS [METHODS ...], --methods METHODS [METHODS ...]
                        HTTP methods to use for testing (e.g., GET POST)
  -v, --verbose         Enable verbose output
```

# Usage:
```
python Headres.py -u http://example.com -m GET POST -v
```
