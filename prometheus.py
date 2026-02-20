#!/usr/bin/python3


#----------------Imports----------------#
import sys
import os.path
import re
import shlex
import pty



#------------Error functions------------#
def usage_standard():
    print(
'''
usage: prometheus.py [-h] (asset_discovery PARAMETERS | blackbox_audit PARAMETERS)

options:
  -h, --help            show this help message and exit

mutually exclusive arguments:
  asset_discovery PARAMETERS
                        Launch asset_discovery.py script in a dockerized environment (All the parameters are passed to the asset_discovery.py script)
  blackbox_audit PARAMETERS
                        Launch blackbox_audit.py script in a dockerized environment (All the parameters are passed to the blackbox_audit.py script)
'''
        )

def usage_asset_discovery():
    print(
'''
usage: prometheus.py asset_discovery [-h] [-n] [-s] [-w] [-g] [-j] [-i] [-S]
                                     [-pc PROVIDER_CONFIGURATION_SUBFINDER]
                                     [-r DNS_RESOLVER_LIST_FILE] -d DIRECTORY
                                     (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...] | -b SUBDOMAIN_LIST_FILE)
options:
  -h, --help            show this help message and exit
  -n, --nuclei          Use Nuclei scanner to scan found assets
  -s, --screenshot      Use EyeWitness to take screenshots of found web assets
  -w, --webanalyzer     Use Webanalyzer to list used web technologies
  -g, --gau             Use gau and katana tools to find interesting URLs on 
                        found web assets
  -j, --js-secrets      Use JSFinder to find secrets in JS files
  -i, --wafwoof         Use wafw00f to determine the WAF technology protecting
                        the found web assets
  -S, --safe            Limit results to subdomains of the provided root domains
  -pc PROVIDER_CONFIGURATION_SUBFINDER, --provider_configuration_subfinder PROVIDER_CONFIGURATION_SUBFINDER
                        Specify a subfinder configuration file to pass API
                        keys for various providers
  -r DNS_RESOLVER_LIST_FILE, --dns-resolver-list DNS_RESOLVER_LIST_FILE
                        Specify a DNS resolver list file that will be used for
                        DNS bruteforcing
required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results
mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of root domains to scan
  -b SUBDOMAIN_LIST_FILE, --bypass-domain-discovery SUBDOMAIN_LIST_FILE
                        Bypass subdomain discovery and pass a subdomain list
'''
        )

def usage_blackbox_audit():
    print(
'''
usage: prometheus.py blackbox_audit [-h] [-e] [-n] [-s] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

options:
  -h, --help            show this help message and exit
  -e, --extended        Run extended tests (includes SSH, FTP, SSL and HTTP tests)
  -n, --nuclei          Use Nuclei scanner to scan assets
  -s, --screenshot      Use Gowitness to take screenshots of web assets

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of domains to scan
'''
        )

def exit_abnormal(function):
    if function == "standard":
        usage_standard()
    elif function == "asset_discovery":
        usage_asset_discovery()
    elif function == "blackbox_audit":
        usage_blackbox_audit()
    sys.exit()



#--------Insert Text after Target-------#
def insert_after_target(text, target, substring):
    # Find the index of the target text
    index = text.find(target)

    # If the target text is found, insert the substring after it
    if index != -1:
        # Slice the string into two parts and insert the substring
        return text[:index + len(target)] + substring + text[index + len(target):]
    else:
        # If target text is not found, return the original text
        return text



#-----Replace last string occurence-----#
def replace_last_occurrence(main_string, old_substring, new_substring):
    # Find the last index of the old_substring
    index = main_string.rfind(old_substring)

    # If the substring is found, replace it
    if index != -1:
        main_string = main_string[:index] + new_substring + main_string[index + len(old_substring):]

    return main_string



#-------Filter Parameters Function------#
def filter_params(command, function):
    final_command = command

    path_args = [
        (r'(-d|--directory)\s+(\S+)', "directory"),
        (r'(-f|--filename)\s+(\S+)', "host list file"),
        (r'(-b|--bypass-domain-discovery)\s+(\S+)', "subdomain list file"),
        (r'(-pc|--provider_configuration_subfinder)\s+(\S+)', "subfinder config"),
        (r'(-r|--dns-resolver-list)\s+(\S+)', "DNS resolver file")
    ]

    for pattern, description in path_args:
        match = re.search(pattern, final_command)

        if match:
            # This is the path the user typed (e.g., 'Asset_Discovery/')
            original_path = match.group(2)
            # Remove trailing slash for consistency
            clean_host_path = original_path.rstrip('/')

            # 1. Check if it exists on the LOCAL machine first
            if not os.path.exists(clean_host_path):
                print(f"\nError! The specified {description}: {clean_host_path} does not exist!\n")
                exit_abnormal(function)

            # 2. Define the Docker-side path
            item_name = clean_host_path.split('/')[-1]
            docker_path = f"/data/{item_name}"

            # 3. Replace the path in the command string
            # We use replace(..., 1) to only change the first occurrence (the argument value)
            if final_command.endswith(original_path):
                final_command = replace_last_occurrence(final_command, original_path, docker_path)
            else:
                final_command = final_command.replace(original_path + " ", docker_path + " ", 1)

            # 4. Mount the volume
            abs_path = os.path.abspath(clean_host_path)
            to_add = f" -v {abs_path}:{docker_path}"

            final_command = insert_after_target(final_command, "-it --rm", to_add)

    return final_command



#----Asset_discovery Launch Function----#
def asset_discovery(params):
    base_command = "docker run -it --rm mtimani/prometheus asset_discovery.py" + params
    to_run = filter_params(base_command, "asset_discovery")

    cmd_list = shlex.split(to_run)

    try:
        pty.spawn(cmd_list)
    except Exception as e:
        print(f"\nError launching Docker: {e}")



#-----Blackbox_audit Launch Function----#
def blackbox_audit(params):
    base_command = "docker run -it --rm mtimani/prometheus blackbox_audit.py" + params
    to_run = filter_params(base_command, "blackbox_audit")

    cmd_list = shlex.split(to_run)

    try:
        pty.spawn(cmd_list)
    except Exception as e:
        print(f"\nError launching Docker: {e}")



#-------------Main Function-------------#
def main():
    ## Print tool logo
    print("""
 ____                           _   _
|  _ \\ _ __ ___  _ __ ___   ___| |_| |__   ___ _   _ ___
| |_) | '__/ _ \\| '_ ` _ \\ / _ \\ __| '_ \\ / _ \\ | | / __|
|  __/| | | (_) | | | | | |  __/ |_| | | |  __/ |_| \\__ \\
|_|   |_|  \\___/|_| |_| |_|\\___|\\__|_| |_|\\___|\\__,_|___/
                                           Version: 1.0.4
                                           Author: mtimani
    """)

    ## Command line arguments
    s = ' '
    cmd_args_list = sys.argv[1:]
    cmd_args = s.join(cmd_args_list)

    ## Check if parameters are passed to the program
    if (not cmd_args):
        exit_abnormal("standard")
    ## Check if the first parameter is asset_discovery or blackbox_audit
    elif not (cmd_args.startswith("asset_discovery") or cmd_args.startswith("blackbox_audit")):
        exit_abnormal("standard")
    ## Display help
    elif (cmd_args.startswith("-h") or cmd_args.startswith("--help")):
        exit_abnormal("standard")

    ## Pass parameters to the asset_discovery function that will launch the asset_discovery.py script in a dockerized environment
    if (cmd_args.startswith("asset_discovery")):
        params = cmd_args.replace("asset_discovery","",1)
        asset_discovery(params)
    ## Pass parameters to the blackbox_audit function that will launch the blackbox_audit.py script in a dockerized environment
    elif (cmd_args.startswith("blackbox_audit")):
        params = cmd_args.replace("blackbox_audit","",1)
        blackbox_audit(params)



#-----------Main Function Call----------#
if __name__ == "__main__":
    main()