#!/usr/bin/python3


#----------------Imports----------------#
import sys
import argparse
import os
import os.path
import subprocess
import socket
import collections
import re
import threading
import tldextract
import json
import alive_progress
import concurrent.futures
import ipaddress
import operator
from cidrize import cidrize



#----------------Colors-----------------#
from termcolor import colored, cprint



#---------------Constants---------------#
dns_bruteforce_wordlist_path    = "/opt/SecLists-DNS/subdomains-top1million-110000.txt"
SANextract_path                 = "/opt/SANextract/SANextract"
webanalyze_path                 = "/usr/bin/webanalyze"
gau_path                        = "/usr/bin/gau"
gowitness_path                  = "/usr/bin/gowitness"
eyewitness_path                 = "/usr/bin/eyewitness"
findomain_path                  = "/usr/bin/findomain"



#-----------Global variables------------#
to_remove                       = []
WAFS                            = {"assets_number":0, "results":{}}



#------------Error functions------------#
def usage():
    print(
'''
usage: asset_discovery.py [-h] [-n] [-s] [-w] [-g] [-i] [-pc PROVIDER_CONFIGURATION_SUBFINDER] -d DIRECTORY
                          (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...] | -b SUBDOMAIN_LIST_FILE)

options:
  -h, --help            show this help message and exit
  -n, --nuclei          Use Nuclei scanner to scan found assets
  -s, --screenshot      Use EyeWitness to take screenshots of found web assets
  -w, --webanalyzer     Use Webanalyzer to list used web technologies
  -g, --gau             Use gau tool to find interresting URLs on found web assets
  -i, --wafwoof         Use wafw00f to determine the WAF technology protecting the found web assets
  -pc PROVIDER_CONFIGURATION_SUBFINDER, --provider_configuration_subfinder PROVIDER_CONFIGURATION_SUBFINDER
                        Specify a subfinder configuration file to pass API keys for various providers

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of root domains to scan
  -b SUBDOMAIN_LIST_FILE, --bypass-domain-discovery SUBDOMAIN_LIST_FILE
                        Bypass subdomain discovery and pass a subdomain list as an argument
'''
        )

def exit_abnormal():
    usage()
    sys.exit()



#----------DNS resolution worker----------#
def dns_worker_f(hostnames):
    for host in hostnames:
        try:
            a = socket.gethostbyname("d5a0a55b307ac269a9333a6d6da1bc108b50581a." + host)
            if (a != ""):
                to_remove.append(host)
        except Exception as e:
            continue



#-------DNS multithreaded resolution------#
def dns_resolver(hostnames):
    ## Variable initialization
    global to_remove 
    to_remove = []
    
    ## Threading initialization
    threads = list()
    chunksize = 100
    chunks = [hostnames[i:i + chunksize] for i in range(0, len(hostnames), chunksize)]
    for chunk in chunks:
        x = threading.Thread(target=dns_worker_f, args=(chunk,))
        threads.append(x)
        x.start()
    for chunk, thread in enumerate(threads):
        thread.join()

    hostnames = [x for x in hostnames if x not in to_remove]

    return(hostnames)



#---------Multithreading Function---------#
def worker_f(directory, root_domain, found_domains, subfinder_provider_configuration_file):
    ## Subfinder
    if (subfinder_provider_configuration_file != "None"):
        bashCommand = "subfinder -silent -d " + root_domain + " -pc " + subfinder_provider_configuration_file
    else:
        bashCommand = "subfinder -silent -d " + root_domain
    
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    for i in output.decode().splitlines():
        found_domains.append(i)
        
    ## Findomain
    bashCommand = findomain_path + " -q -t " + root_domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    for i in output.decode().splitlines():
        if i != "":
            found_domains.append(i)
    
    ## Aiodnsbrute
    bashCommand = "aiodnsbrute -w " + dns_bruteforce_wordlist_path + " -t 1024 " + root_domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    ### Found subdomains extraction
    out = output.decode().splitlines()
    substring = '[+]'
    temp = [item for item in out if substring.lower() in item.lower()]
    for i in temp:
        found_domains.append(i.split('[0m',1)[1].split('\t',1)[0].strip())



#--------Domains Discovery Function-------#
def first_domain_scan(directory, hosts, subfinder_provider_configuration_file):
    ## Root and found domains list initialization
    root_domains  = hosts.copy()
    found_domains = hosts.copy()

    ## Print to console
    cprint("\nFinding subdomains for specified root domains:", 'red')

    for domain in root_domains:
        print('- ' + domain)

    counter = len(root_domains)

    ## Loop over root domains
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'Subdomain search and bruteforce (Can take time)') as bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_f = {executor.submit(worker_f, directory, root_domain, found_domains, subfinder_provider_configuration_file): root_domain for root_domain in root_domains}
            
            for future in concurrent.futures.as_completed(future_f):
                bar()
    
    ## Sort - Uniq Found domains list
    found_domains = sorted(set(found_domains))

    return found_domains.copy()



#-------------httpx Function--------------#
def httpx_f(directory, subdomain_list_file):
    ## Print to console
    cprint("\nRunning httpx, a project discovery tool on the provided subdomains\n", 'red')

    ## httpx - project discovery
    bashCommand = "httpx -l " + subdomain_list_file + " -t 150 -rl 3000 -p http:80,https:443,http:8080,https:8443,http:8000,http:3000,http:5000,http:10000 -timeout 3 -probe"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    out = output.decode().splitlines()

    urls = []

    for line in out:
        if ("FAILED" not in line):
            url = line.split('[')[0].strip()
            urls.append(url)

    with open(directory + "/httpx_results.txt", "w") as fp:
        for item in urls:
            fp.write("%s\n" % item)



#--------Domains Discovery Function-------#
def domains_discovery(directory, hosts, subfinder_provider_configuration_file):
    ## First domain scan function call
    found_domains = first_domain_scan(directory, hosts, subfinder_provider_configuration_file)

    ## Remove wildcard domains
    cprint("Running wildcard DNS cleaning function\n", 'red')
    cleaned_domains = dns_resolver(found_domains)

    ## httpx - project discovery
    cprint("Running httpx\n", 'red')

    with open(directory + "/found_domains.txt.tmp", "w") as fp:
        for item in cleaned_domains:
            fp.write("%s\n" % item)

    bashCommand = "httpx -l " + directory + "/found_domains.txt.tmp -t 150 -rl 3000 -p http:80,https:443,http:8080,https:8443,http:8000,http:3000,http:5000,http:10000 -timeout 3 -probe"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    out = output.decode().splitlines()
    
    urls = []

    for line in out:
        if ("FAILED" not in line):
            url = line.split('[')[0].strip()
            urls.append(url)

    with open(directory + "/httpx_results.txt", "w") as fp:
        for item in urls:
            fp.write("%s\n" % item)

    if os.path.exists(directory + "/found_domains.txt.tmp"):
        os.remove(directory + "/found_domains.txt.tmp")

    ## SANextract
    cprint("Running SANextract\n", 'red')

    temp = []
    for i in urls:
        bashCommand_1 = "echo " + i
        bashCommand_2 = SANextract_path + " -timeout 1s"
        p1 = subprocess.Popen(bashCommand_1.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(bashCommand_2.split(), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for j in p2.stdout.read().decode().splitlines():
            if len(j) != 0:
                if j[0] != '*':
                    temp.append(j)

    ## Remove wildcard domains (again)
    cprint("Running wildcard DNS cleaning function\n", 'red')
    cleaned_temp = dns_resolver(temp)
    cleaned_domains.extend(cleaned_temp)
    cleaned_domains = sorted(set(cleaned_domains))

    ## Write found domains to a file
    with open(directory+"/domain_list.txt","w") as fp:
        for item in cleaned_domains:
            fp.write("%s\n" % item)

    return cleaned_domains



#---------IP Discovery Function---------#
def IP_discovery(directory, found_domains):
    ## Print to console
    cprint("Finding IPs for found subdomains\n",'red')

    ## Variables initialization
    ip_dict = {}
    ip_list = []
    keys = range(len(found_domains))

    counter = len(found_domains)

    ## IP addresses lookup
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'IP address resolution') as bar:
        for domain in found_domains:
            bar()
            try:
                ais = socket.getaddrinfo(domain,0,socket.AF_INET,0,0)
                IPs = []
                for result in ais:
                    IPs.append(result[-1][0])
                    ip_list.append(result[-1][0])
                IPs = sorted(set(IPs))
                ip_dict[domain] = IPs.copy()
            except:
                None
    
    ## Sort and uniq IP addresses
    ip_list = sorted(set(ip_list))

    ## Write found IPs to a file
    with open(directory+"/IPs.txt","w") as fp:
        for item in ip_list:
            fp.write("%s\n" % item)

    return (ip_list,ip_dict)



#-------------Whois Function------------#
def whois(directory,ip_list,ip_dict):
    ## Print to console
    cprint("Whois magic\n",'red')

    ## Create Whois directory
    try:
        os.mkdir(directory+"/Whois")
    except FileExistsError:
        None
    except:
        raise

    ## Variable initialization
    whois_list = []
    whois_dict = {}

    counter = len(ip_list)

    ## Whois list retreival
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'Whois resolution') as bar:
        for ip in ip_list:
            bar()
            try:
                bashCommand = "whois " + ip
                process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                whois_list.append(output.decode().lower())
            except:
                cprint("Error: Failed to whois the following IP address : " + ip + "\n", 'red')

    ## Sort - Uniq on the retreived whois_list
    whois_list = sorted(set(whois_list))

    ## Find correct name for whois file and write to file
    value_1 = "inetnum:"
    value_2 = "cidr:"
    cnt     = 0
    for whois_element in whois_list:
        ### Variable initialization
        filename = ""

        ### Loop through lines of whois output
        for line in whois_element.splitlines():
            if (value_1 in line):
                filename = line.strip().split(":")[1].replace(" ", "").strip().split(",")[0].strip()
            elif (value_2 in line):
                filename = line.strip().split(":")[1].replace(" ", "").strip().split(",")[0].strip()
                break
        
        ## Uniformize Filename
        try:
            cidr = str(cidrize(filename, strict=True)[0])
            filename = cidr.replace("/","_").strip() + ".txt"
            cnt += 1
        except:
            cprint("Cidrize failed for: " + filename + "\n", "red")
            continue

        ### Write to file
        with open(directory + "/Whois/" + filename,"w") as fp:
            fp.writelines(whois_element)

        ### Complete dictionnary
        value_3  = "organization:"
        value_4  = "org-name:"
        value_5  = "netname:"
        value_6  = "org:"
        ip_owner = ""
        for line in whois_element.splitlines():
            if (value_3 in line) or (value_4 in line) or (value_5 in line) or (value_6 in line):
                ip_owner = line.split(":")[1].strip()
                break
        
        if (cidr not in whois_dict):
            percentage  = round(1 / counter * 100,2)
            l = {'Owner': ip_owner, 'Counter': 1, 'Percentage': percentage}
            whois_dict[cidr] = l
        else:
            whois_dict[cidr]['Counter'] += 1
            percentage = round(whois_dict[cidr]['Counter'] / counter * 100,2)
            whois_dict[cidr]['Percentage'] = percentage

    for cidr in whois_dict:
        percentage = round(whois_dict[cidr]['Counter'] / cnt * 100, 2)
        whois_dict[cidr]['Percentage'] = percentage

    ## Append IP Network Owner
    for dict1_key in ip_dict.keys():
        ip = ip_dict[dict1_key][0]
        for dict2_key in whois_dict.keys():
            if ipaddress.ip_address(ip) in ipaddress.ip_network(str(dict2_key)):
                ip_dict[dict1_key].append(dict2_key)
                ip_dict[dict1_key].append(whois_dict[dict2_key])
    ### Write Domains and corresponding IPs to a json file
    with open(directory+"/domain_and_IP_list.json","w") as fp:
        fp.write(json.dumps(ip_dict, sort_keys=True, indent=4))
 
    ## Write whois dictionnary to file
    with open(directory+"/IP_ranges_and_owners.txt","w") as fp:
        fp.write("{:<40} | {:<40}\n".format('IP Range', 'Owner'))
        for ip_range, l in whois_dict.items():
            owner = l["Owner"]
            percentage = str(l["Percentage"]) + " %"
            fp.write("{:<40} | {:<60} | {:<40}\n".format(ip_range, owner, percentage))

    ## Subdomain distribution stats
    ### Variable initialization
    subdomain_stats = {}

    ### Recover root domains
    for key in ip_dict.keys():
        root_domain = tldextract.extract(key).registered_domain
        if root_domain in subdomain_stats:
            subdomain_stats[root_domain] += 1
        else:
            subdomain_stats[root_domain] = 1

    sorted_subdomain_stats = dict( sorted(subdomain_stats.items(), key=operator.itemgetter(1),reverse=True))
    with open(directory + "/subdomain_distribution.csv","w") as fp:
        for key in sorted_subdomain_stats.keys():
            line = key + "," + str(subdomain_stats[key]) + "\n"
            fp.write(line)



#--------Parse percentage function-------#
def parse_percentage(text):
    # Extract percentage from text
    float_value = float(re.search(r'\d+\.\d+', " 1.54 %").group())
    return float_value



#----Statistics normalization function---#
def owner_percentage_normalization_f(directory):
    owner_percentages_not_sorted = collections.defaultdict(dict)
    owner_percentages = collections.defaultdict(dict)

    with open(directory + '/IP_ranges_and_owners.txt', 'r') as fp:
        # Skip the header row
        next(fp)
        for line in fp:
            ip_range, owner, percentage_text = line.strip().split('|')
            owner_name = owner.strip()
            percentage = parse_percentage(percentage_text)
            if owner_name in owner_percentages_not_sorted:
                owner_percentages_not_sorted[owner_name]["percentage"] += percentage
                owner_percentages_not_sorted[owner_name]["ip_range"] = owner_percentages_not_sorted[owner_name]["ip_range"] + ", " + ip_range
            else:    
                owner_percentages_not_sorted[owner_name] = {"ip_range": ip_range, "percentage": percentage}

    # Sort lines by percentages
    while owner_percentages_not_sorted:
        max_owner_name = ""
        max_ip_range_string = ""
        max_percentage = 0
        for owner_name, range_and_percentage in owner_percentages_not_sorted.items():
            if range_and_percentage["percentage"] > max_percentage:
                max_owner_name = owner_name
                max_ip_range_string = range_and_percentage["ip_range"]
                max_percentage = range_and_percentage["percentage"]
        owner_percentages[max_owner_name] = {"ip_range": max_ip_range_string, "percentage": max_percentage}
        owner_percentages_not_sorted.pop(max_owner_name, None)

    # Calculate total percentage
    total_percentage = 0
    for owner_name, range_and_percentage in owner_percentages.items():
        total_percentage += range_and_percentage["percentage"]

    # Write normalized output to file
    if total_percentage > 0:
        with open(directory + '/IP_ranges_and_owners.txt', 'w') as fp:
            fp.write("{:<60} | {:<47} | {:<1}\n".format('Owner', 'Percentage', 'IP Ranges'))
            for owner_name, range_and_percentage in owner_percentages.items():
                relative_percentage = round(range_and_percentage["percentage"] / total_percentage * 100, 3)
                ip_range_string = range_and_percentage["ip_range"]
                fp.write("{:<60} | {:<6} {:<40} | {:<1}\n".format(owner_name, relative_percentage, "%", re.sub("\s+" , " ", ip_range_string)))
    else:
        cprint("No unique owners found.", "red")



#------Determine WAF worker Function-----#
def determine_waf_worker(url):
    ## Variable declaration
    global WAFS

    ## Wafw00f scan launch
    try:
        bashCommand = "wafw00f " + url
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        ### Bash color removal 
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        response = ansi_escape.sub('', output.decode())

        ## Result extraction
        if ("is behind" in response):
            waf = re.findall(r'is behind (.*) WAF', response)[0]
        elif ("seems to be behind a WAF or some sort of security solution" in response):
            waf = "No WAF"
        elif ("No WAF detected by the generic detection" in response):
            waf = "No WAF"

        ### Append Data to WAFS dictionnary
        WAFS["assets_number"] += 1
        if (waf not in WAFS["results"]):
            WAFS["results"][waf] = {"counter":1, "urls":[url]}
        else:
            WAFS["results"][waf]["counter"] += 1
            WAFS["results"][waf]["urls"].append(url)
    
    except:
        if ("Failed" not in WAFS["results"]):
            WAFS["results"]["Failed"] = {"counter":1, "urls":[url]}
        else:
            WAFS["results"]["Failed"]["counter"] += 1
            WAFS["results"]["Failed"]["urls"].append(url)

    

#---------Determine WAF Function---------#
def determine_waf(directory):
    ## Print to console
    cprint("Finding WAFs located in front of the found web assets with wafw00f\n", 'red')

    ## Constants declarations
    urls = []

    ## Open httpx_results file and injest data
    ### Check if httpx_results.txt file exists
    if not os.path.exists(directory + "/httpx_results.txt"):
        cprint("\nFailed finding WAFs located in front of the found web assets with wafw00f!\n", 'red')
        cprint("\nThe file: " + directory + "/httpx_results.txt" + " cannot be found!\n", 'red')
    else:
        with open(directory + "/httpx_results.txt", "r") as fp:
            urls = fp.read().splitlines()

        counter = len(urls)

        ## Loop through urls & multithread
        with alive_progress.alive_bar(counter, ctrl_c=True, title=f'wafw00f progress') as bar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_f = {executor.submit(determine_waf_worker, url): url for url in urls}
                
                for future in concurrent.futures.as_completed(future_f):
                    bar()

        ## Output result to file
        with open(directory + "/waf_results.json","w") as fp:
            fp.write(json.dumps(WAFS, sort_keys=True, indent=4))



#---------Nuclei Function Launch--------#
def nuclei_f(directory, domain_list_file = "/domain_list.txt"):
    ## Print to console
    cprint("Nuclei scan launched!\n",'red')

    ## Create Nuclei output directory
    dir_path = directory + "/Nuclei"
    try:
        os.mkdir(dir_path)
        cprint("Creation of " + dir_path + "/ directory", 'blue')
    except FileExistsError:
        cprint("Directory " + dir_path + "/ already exists", 'blue')
    except:
        raise
    
    ## Nuclei scan launch
    ### If root domain list is provided
    if (domain_list_file == "/domain_list.txt"):
        bashCommand = "nuclei -l " + directory + "/domain_list.txt -o " + dir_path + "/nuclei_all_findings.txt"
    ### If subdomain list is provided
    else:
        bashCommand = "nuclei -l " + domain_list_file + " -o " + dir_path + "/nuclei_all_findings.txt"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    ## Extract interresting findings
    with open(dir_path + "/nuclei_all_findings.txt", "r") as f_read:
        with open(dir_path + "/nuclei_important_findings.json", "w") as f_write:
            ### Variable initialization
            to_write    = {"critical": [], "high": [], "medium": [], "low": [], "other": []}
            to_remove_1 = "[dns]"
            to_remove_2 = "[info]"
            critical    = "[critical]" 
            high        = "[high]"
            medium      = "[medium]"
            low         = "[low]"
            
            for line in f_read.readlines():
                l = line.rstrip()
                if ((to_remove_1 not in l) and (to_remove_2 not in l)):
                    if (l != "]"):
                        if (critical in l):
                            to_write["critical"].append(l)
                        elif (high in l):
                            to_write["high"].append(l)
                        elif (medium in l):
                            to_write["medium"].append(l)
                        elif (low in l):
                            to_write["low"].append(l)
                        else:
                            to_write["other"].append(l)

            f_write.write(json.dumps(to_write, indent=4))



#---------Screenshot Function Launch--------#
def screenshot_f(directory, domain_list_file = "/domain_list.txt"):
    ## Print to console
    cprint("Screenshots of found web assets with EyeWitness launched!\n",'red')
    
    ## EyeWitness tool launch
    ### If root domain list is provided
    if (domain_list_file == "/domain_list.txt"):
        os.system(eyewitness_path + " --timeout 10 --prepend-https --no-prompt --delay 5 -d " + directory + "/Screenshots -f " + directory + "/domain_list.txt")
    ### If subdomain list is provided
    else:
        os.system(eyewitness_path + " --timeout 10 --prepend-https --no-prompt --delay 5 -d " + directory + "/Screenshots -f " + domain_list_file)



#-------Webanalyzer Worker Launch-------#
def webanalyzer_worker(directory, domain):
    ### Check if ports are open
    try:
        web_port = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((domain,80))
        if result == 0:
            web_port = True
        result = sock.connect_ex((domain,443))
        if result == 0:
            web_port = True
    except:
        web_port = False

    ### Analyze
    try:
        if web_port:
            os.system(webanalyze_path + " -host " + domain + " -output json -silent -search false -redirect 2>/dev/null | jq > " + directory + "/Webanalyzer/" + domain + ".json 2>/dev/null")
    except:
        cprint("\tError running Webanalyzer for " + domain + "\n", 'red')



#-------Webanalyzer Function Launch------#
def webanalyzer_f(directory, found_domains):
    ## Print to console
    cprint("Finding used technologies by the found web assets with Webanalyzer:\n", 'red')

    ## Create output directories
    try:
        os.mkdir(directory + "/Webanalyzer")
        cprint("Creation of " + directory + "/Webanalyzer/ directory", 'blue')
    except FileExistsError:
        cprint("Directory " + directory + "/Webanalyzer/ already exists", 'blue')
    except:
        raise

    ## Update Webanalyze
    try:
        os.system(webanalyze_path + " -update")
    except:
        raise

    counter = len(found_domains)

    ## Loop through found domains & multithread
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'Webanalyze progress') as bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            future_f = {executor.submit(webanalyzer_worker, directory, domain): domain for domain in found_domains}
            
            for future in concurrent.futures.as_completed(future_f):
                bar()

    ## Remove empty files
    for (dirpath, folder_names, files) in os.walk(directory + "/Webanalyzer/"):
        for filename in files:
            file_location = dirpath + '/' + filename
            if os.path.isfile(file_location):
                if os.path.getsize(file_location) == 0:
                    os.remove(file_location)

    ## Statistics
    technologies = {}
    for (dirpath, folder_names, files) in os.walk(directory + "/Webanalyzer/"):
        for filename in files:
            file_location = dirpath + '/' + filename
            filename_domain = filename.split('.json')[0]
            if os.path.isfile(file_location):
                with open(file_location, "r") as fp:
                    try:
                        technologies_detailed_list = json.load(fp)['matches']
                        for element in technologies_detailed_list:
                            techs = element['app_name']
                        if techs in technologies:
                            technologies[techs]['number'] += 1
                        else:
                            technologies[techs] = {"number": 1, "versions": [], "hostname_versions": {}}
                        if element['version'] != "":
                            technologies[techs]['versions'].append(element['version'])
                            technologies[techs]['hostname_versions'][filename_domain] = element['version']
                        else:
                            technologies[techs]['hostname_versions'][filename_domain] = "NaN"
                    except:
                        cprint("\tError running webanalyzer for: " + filename_domain + "\n", 'red')

    ## Write technologies statistics to file
    with open(directory + "/technologies_statistics.json", "w") as fp:
        fp.write(json.dumps(technologies, sort_keys=False, indent=4))



#--------------Gau Function-------------#
def gau_f(directory, domain_list_file = "/domain_list.txt"):
    ## Print to console
    cprint("Finding interresting URLs based on found web assets\n", 'red')

    ## Launch Gau Tool
    try:
        ### If root domain list is provided
        if (domain_list_file == "/domain_list.txt"):
            os.system("cat " + directory + "/domain_list.txt | " + gau_path + " --o " + directory + "/gau_url_findings.txt --providers wayback,commoncrawl,otx")
        ### If subdomain list is provided
        else:
            os.system("cat " + domain_list_file + " | " + gau_path + " --o " + directory + "/gau_url_findings.txt --providers wayback,commoncrawl,otx")
    except:
        cprint("\t Error running gau tool on found web assets\n", 'red')



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')
    exclusive   = parser.add_argument_group('mutually exclusive arguments')
    content     = exclusive.add_mutually_exclusive_group(required=True)

    ## Arguments
    parser.add_argument("-n", "--nuclei", dest='n', action='store_true', help="Use Nuclei scanner to scan found assets")
    parser.add_argument("-s", "--screenshot", dest='s', action='store_true', help="Use EyeWitness to take screenshots of found web assets")
    parser.add_argument("-w", "--webanalyzer", dest='w', action='store_true', help="Use Webanalyzer to list used web technologies")
    parser.add_argument("-g", "--gau", dest='g', action='store_true', help="Use gau tool to find interresting URLs on found web assets")
    parser.add_argument("-i", "--wafwoof", dest='i', action='store_true', help="Use wafw00f to determine the WAF technology protecting the found web assets")
    parser.add_argument("-pc", "--provider_configuration_subfinder", dest="provider_configuration_subfinder", help="Specify a subfinder configuration file to pass API keys for various providers")
    required.add_argument("-d", "--directory", dest="directory", help="Directory that will store results", required=True)
    content.add_argument("-f", "--filename", dest="host_list_file", help="Filename containing root domains to scan")
    content.add_argument("-l", "--list", dest="host_list", nargs='+', help="List of root domains to scan")
    content.add_argument("-b", "--bypass-domain-discovery", dest="subdomain_list_file", help="Bypass subdomain discovery and pass a subdomain list as an argument")
    return parser



#-------------Main Function-------------#
def main(args):
    ## Arguments
    directory                           = args.directory
    host_list                           = args.host_list
    host_list_file                      = args.host_list_file
    subdomain_list_file                 = args.subdomain_list_file
    provider_configuration_subfinder    = args.provider_configuration_subfinder
    do_nuclei                           = args.n
    do_screenshots                      = args.s
    do_webanalyzer                      = args.w
    do_gau                              = args.g
    do_wafwoof                          = args.i

    ## Display welcome message
    print()
    cprint("⚙️  Configuration:", "blue")
    print("- Subscript: ", end='')
    cprint("Asset_Discovery", "green")
    

    ## Check if Output Directory exists
    if (not(os.path.exists(directory))):
        cprint("\nError! The specified output directory: %s does not exist!\n" % (directory), 'red')
        exit_abnormal()
    # Output to config output
    print("- Output Directory: ", end='')
    cprint("%s" % (directory), "green")

    ## Hosts list creation
    
    ### Hosts list variable creation
    hosts = []
    subdomains = []
    
    ### If option -f is specified
    if (host_list_file != None):
        if (not(os.path.exists(host_list_file))):
            cprint("\nError! The specified host list file: %s does not exist!\n" % (host_list_file), 'red')
            exit_abnormal()
        with open(host_list_file) as file:
            for line in file:
                hosts.append(line.replace("\n", ""))
        # Output to config output
        print("- Root domain list file: ", end='')
        cprint("%s" % (host_list_file), "green")
    ### If option -b is specified
    elif (subdomain_list_file != None):
        if (not(os.path.exists(subdomain_list_file))):
            cprint("\nError! The specified subdomain list file: %s does not exist!\n" % (subdomain_list_file), 'red')
            exit_abnormal()
        with open(subdomain_list_file) as file:
            for line in file:
                subdomains.append(line.replace("\n", ""))
        # Output to config output
        print("- Subdomains list file: ", end='')
        cprint("%s" % (subdomain_list_file), "green")
    ### If option -l is specified
    else:
        hosts = host_list
        # Output to config output
        print("- Root domains list: ", end='')
        cprint("%s" % (host_list), "green")

    ## Output to config output
    if (not subdomains):
        print("- Perform subdomain enumeration => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform subdomain enumeration => ", end='')
        cprint("NO", "red")

    if (provider_configuration_subfinder != None):
        if (not(os.path.exists(provider_configuration_subfinder))):
            cprint("\nError! The specified subfinder provider configuration file: %s does not exist!\n" % (provider_configuration_subfinder), 'red')
            exit_abnormal()
        subfinder_provider_configuration_file = provider_configuration_subfinder
        # Output to config output
        print("- Subfinder provider configuration file: ", end='')
        cprint("%s" % (subfinder_provider_configuration_file), "green")

    if (do_wafwoof):
        print("- Perform WAF enumeration => ", end='')
        cprint("YES", "green")        
    else:
        print("- Perform WAF enumeration => ", end='')
        cprint("NO", "red")
    if (do_webanalyzer):
        print("- Perform Web Technologies enumeration => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform Web Technologies enumeration => ", end='')
        cprint("NO", "red")
    if (do_gau):
        print("- Perform GAU interresting URLs enumeration => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform GAU interresting URLs enumeration => ", end='')
        cprint("NO", "red")
    if (do_screenshots):
        print("- Capture Screenshots on found subdomains => ", end='')
        cprint("YES", "green")
    else:
        print("- Capture Screenshots on found subdomains => ", end='')
        cprint("NO", "red")
    if (do_nuclei):
        print("- Perform Nuclei Scan => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform Nuclei Scan => ", end='')
        cprint("NO", "red")

    ## Domains discovery function call in the case subdomains are not provided and only root domains are provided
    if (not subdomains):
        if (provider_configuration_subfinder != None):
            found_domains = domains_discovery(directory, hosts, subfinder_provider_configuration_file)
        else:
            found_domains = domains_discovery(directory, hosts, "None")

    ## Httpx Function call (that runs httpx on the provided subdomains) if subdomain option is selected
    if (subdomains):
        httpx_f(directory, subdomain_list_file)
        

    ## IP discovery function call
    ### If root domain list is provided
    if (not subdomains):
        ip_list, ip_dict = IP_discovery(directory, found_domains)
    ### If subdomain list is provided
    else:
        ip_list, ip_dict = IP_discovery(directory, subdomains)

    ## Whois function call
    whois(directory, ip_list, ip_dict)

    ## Statistics normalization function call
    owner_percentage_normalization_f(directory)

    ## Run WAF related tests
    if (do_wafwoof):
        determine_waf(directory)

    ## Webanalyzer function call
    if (do_webanalyzer):
        ### If root domain list is provided
        if (not subdomains):
            webanalyzer_f(directory, found_domains)
        ### If subdomain list is provided
        else:
            webanalyzer_f(directory, subdomains)

    ## Gau function call
    if (do_gau):
        ### If root domain list is provided
        if (not subdomains):
            gau_f(directory)
        ### If subdomain list is provided
        else:
            gau_f(directory, subdomain_list_file)

    ## Take screenshots of found web assets if -s is specified
    if (do_screenshots):
        ### If root domain list is provided
        if (not subdomains):
            screenshot_f(directory)
        ### If subdomain list is provided
        else:
            screenshot_f(directory, subdomain_list_file)

    ## Nuclei scan if -n is specified
    if (do_nuclei):
        ### If root domain list is provided
        if (not subdomains):
            nuclei_f(directory)
        ### If subdomain list is provided
        else:
            nuclei_f(directory, subdomain_list_file)

    cprint("\nAll tests complete, good hacking to you young padawan!",'green')



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
