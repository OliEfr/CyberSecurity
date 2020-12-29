# CyberSecurity
[TryHackMe](https://tryhackme.com/) is a great platform to get started with cyber security! Most resources listed here I learned about at the TryHackMe AdventOfCyber2.
## Web
- HTTP is stateless &rarr; (server-)session identification with cookies stored on client (i.e. web browser)
    - Cookies can only be access by sites of same domain
- URL: subdomain.domain.TLD/ressource?param=value, i.e. www.test.de/index.html?param1=1&param2=2
- Reverse shells:
    - Try to load and execute a reverse shell on the remote-machine!
    - Listener: sudo netcat -lvnp {port}
    - Port: use common, open ports, such as 443 or 80
    - Revere-Shell [Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp)
    - Upgrading a (reverse) shell:
        1. python3 -c 'import pty;pty.spawn("/bin/bash")'
        2. export TERM=xterm
        3. Ctrl + Z
        4. stty raw -echo; fg
        &rarr; Now you can use: tab autocomplete, arrow keys, and ctrl+c

- BurpSuite: track http-traffic & dictionary attacks on websites
    - Perform dictionary attacks by iterating through a list of credentials (e.g. rockyou.txt) for a specific http-request
        1. Intercept traffic by proxying through BurpSuite (use FoxyProxy extension in Firefox or build-in browser)
        2. Select request with credentials & send to "Intruder" tab
        3. Select payloads for each position
        4. Start attack
    - BurpSuite can also be used to track all network requests drop specific requests
- Discovering web-site directories and bruteforcing url parameters:
    - gobuster: Bruteforce common paths (files and folders), aka 'enumerating a website'
        - example: gobuster {-m} {dir} -u http://example.com -w wordlist.txt -x php,txt,html -t 40
    - wfuzz: replace url parts with wordlists (e.g. parameters)
        - example: wfuzz -c -z file,mywordlist.txt -d “username=FUZZ&password=FUZZ” -u http://shibes.thm/login.php
        - example: wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ
    - wordlist for common paths & folder names: [big.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt)
- SQLMap: tool that automates the process of detecting and exploiting SQL injection flaws on websites
    - Install: git clone --depth 1 <https://github.com/sqlmapproject/sqlmap.git> sqlmap-dev
    - [Cheatsheet](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet)
    - bypass WAF with --tamper=space2comment flag
    - Workflow:
        1. Submit a request on the web application we suspect to be vulnerable
        2. Intercept request with BurpSuite
        3. Send request to repeater & save request in file
        4. sqlmap -r filename &rarr; will automatically exploit database
- XSS (Cross-Site Scripting):
    - stored XSS: store malicious js on the website, e.g. leave comment on website containing a \<script> tag 
    - reflected XSS (embed in url): domain.de/reflected?keyword=\<script>alert(1)\</script>
    - XSS Payloads: [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) and [here](https://github.com/payloadbox/xss-payload-list)
- OWASP ZAP: open-source web application security scanner to automatically detect web vulnerabilities for a website
    - just use the automated scan
- Preventing XSS and SQLi
    -  all user input should be sanitized at both the client and server-side so that potentially malicious characters are removed
    - Smart developers should always implement a filter to any text input field and follow a strict set of rules regarding processing the inputted data, see [cheatsheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md)
- Wireshark: Wireshark is capable of recording a log of all the packets sent and received on a computer's network adapter
- nmap: most important port scanning tool
    - common options: -sS | -T{0-5} | -A | -O | -sV | -Pn
    - use scripting engine to performe advanced analysis tasks:
        - https://nmap.org/nsedoc/scripts/
        - exapmle: nmap --script ftp-proftpd-backdoor -p 21 {ip_address}
    - protect against nmap scans with IDS & IPS Systems: Snort or Suricata. These services need to be installed on a firewall such as pfSense.
- Server-Side Requst Forgery: vulnerability that allows attackers to force the web application server to make requests to resources it normally wouldn't
- bypass upload filter (e.g. to upload a reverse shell script):
    - client-side filtering: block request using e.g. BurpSuite; this way, js-files can be dropped
    - server-side filtering: of often these filters fitler by file-extension. Avoid these filters by naming files as follows: FILE.jpg.php

## Enumeration
Enumeration for priviledge escalation. Guides:
- [manual enumeration cheatsheet](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation)
- [more verbose guide for enumeration](https://payatu.com/guide-linux-privilege-escalation)
- [complete cheatsheet and toollist for enumeration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#tools)
- automated enumeration with [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)

## Priviledge Escalation
- Databse of Binaries that can be used to escalate priviledges can be found [here](https://gtfobins.github.io/)

## Knowledge bases for exploits
- most software has known vulnarabilities. These are collected and databases
- Vulnarabilities can be found by searching for software + version-number
- vulnerabilities are identified with a CVE-Number
- [exploit-db](https://www.exploit-db.com/)
- ([rapid7](https://www.rapid7.com/))
- ([mitre](https://cve.mitre.org/cve/))

## Exploit known vulnarabilities with metasploit
- first, look up a vulnarability for your version of a software in a knowledge database. Then use metasploit to exploit that vulnarabitlity
- start metasploit with "msfconsole -q"
- search {CVE} &rarr; matching exploits (modules) are listet
- "use {number}" to use a exploit
- Now the module is loaded. Type "options" to configure the exploit.
- type "run" to run the exploit. After finished, type "shell" to open a shell on the target machine.

## Analyzing binaries
- radare2 (for any binary): shows all functions in the binary and their assembly code
    1. r2 -d ./file1 (open binary in debug mode)
    2. aa (analyse)
    3. afl (get list of all functions)
    4. dpf @main (get assembly code of main function)
    5. step through the assembly code by using "db" (set breakpoints) and "dc" (run until breakpoint) and "ds" (execute next command)
    6. inspect variables using "px"
    
    Hint: Reload program using ood
- for .NET Applications: use ILSpy (or Dotpeek). These tools show the code of .NET applications.

## Windows
- ADS: Alternate Data Stream, a file attribute specific to NTFS
    - Learn more about ADS [here](https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/), [here](https://blog.foldersecurityviewer.com/ntfs-alternate-data-streams-the-good-and-the-bad/) and [here](http://www.winfaq.de/faq_html/Content/tip1500/onlinefaq.php?h=tip1915.htm)
    - tool to analyse a binary file (.exe): Strings.exe. Strings scans the file you pass it for strings of a default length of 3 or more characters. You can use the Strings tool to peek inside this mysterious executable file. Usage: strings64.exe -accepteula file.exe


## Other Tools and resources
- samba enumeration with the enum4linux.pl tool
- [CyberChef] (https://gchq.github.io/CyberChef/)
    - is a 'Cyber Swiss-Army Knife'
    - provides numerous functions for all tasks: encoding, decoding, hashing ...
    - With the "Magic"-recipe you can analyse any given string to detect useful encoding methods.
- lists:
        -  https://github.com/danielmiessler/SecLists/ (espacially rockyou.txt for passwords)
- Crack hashes online (rainbow tables):
    - https://crackstation.net/ 
    - https://md5decrypt.net/en/ 
    - https://hashes.com/en/decrypt/hash 
- [OWASP](https://owasp.org/): Provides a lot of tools, knowledge and other resources regarding cyber security in the web
- [OWASP Cheatsheets](https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets) for everything related to cybersecurity

