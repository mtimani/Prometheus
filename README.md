# Prometheus

Welcome to the Prometheus repo!

![3f6cfea3-dbb2-405c-bb57-bd410496bec3](https://github.com/user-attachments/assets/fa21ec5f-1fed-4bc5-94c2-2851b928dc52)


## Description

Prometheus is a collection of two recon scripts for Red Team and Web blackbox auditing:

- **asset_discovery**: a small script that allows to perform DNS asset discovery, Nuclei scans, determine used technologies, find known URLs, take screenshots of found web assets by combining the output of several tools.
- **blackbox_audit**: script that does a lot of blackbox tests (Ping, Nmap, DNS+DNSSec tests, sslscan + testssl) on a set of hosts you provide to the script.

To start, check the [Installation](../../wiki/2.-Installation) page and the [Recommended User Guide](../../wiki/3.-User-Guide-‐-With-Docker-‐-Recommended) that describes the usage of the tool with a Docker container and a simple wrapper script.

Alternatively you can check the [Not Recommended User Guide](../../wiki/4.-User-Guide-‐-Standalone-‐-Not-recommended) that describes the usage of the recon scripts without Docker container.

## Disclaimer
This tool is intended for educational purposes only. Performing hacking attempts on computers that you do not own (without permission) is illegal! Do not attempt to gain access to devices that you do not own.

## asset_discovery is using the following tools to generate its results 
**Subdomain Discovery**:
- subfinder (https://github.com/projectdiscovery/subfinder)
- findomain (https://github.com/Findomain/Findomain)
- aiodnsbrute (https://github.com/blark/aiodnsbrute)
- SANextract (https://github.com/hvs-consulting/SANextract)

**Additionnal Tools**:
- httpx (https://github.com/projectdiscovery/httpx)
- nuclei (https://github.com/projectdiscovery/nuclei)
- gau (https://github.com/lc/gau)
- webanalyze (https://github.com/rverton/webanalyze)
- eyewitness (https://github.com/RedSiege/EyeWitness)
- wafw00f (https://github.com/EnableSecurity/wafw00f)

## blackbox_audit is using the following tools to generate its results
- nslookup
- dig
- ping
- nmap
- testssl.sh (https://github.com/drwetter/testssl.sh)
- ssh-audit (https://github.com/jtesta/ssh-audit)
- httpmethods (https://github.com/ShutdownRepo/httpmethods)
- gau (https://github.com/lc/gau)
- webanalyze (https://github.com/rverton/webanalyze)
- wafw00f (https://github.com/EnableSecurity/wafw00f)
- gowitness (https://github.com/sensepost/gowitness)
