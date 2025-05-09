#!/usr/bin/zsh

# Colors setup
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
initial_dir=$(pwd)

#Check if script is ran as root
if [ "$EUID" -ne 0 ]
  then echo "${RED}Please run as root!${NC}"
  exit
fi

# Check OS
OS=$(lsb_release -a 2>/dev/null | grep 'Distributor ID' | awk '{print $3}')
if [ "$(echo $HOSTNAME | awk -F '-' '{print $1}')" = "exegol" ]; then
    OS="Exegol"
    source /opt/.exegol_aliases
fi

# Echo information
if [ "$OS" = "Kali" ]; then
    echo "\n${GREEN}Kali Linux detected. The script can proceed with installation${NC}\n"
elif [ "$OS" = "Exegol" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
    echo "\n${GREEN}$OS detected. The script can proceed with installation${NC}\n"
else
    echo "\n${RED}This script has to be ran in Kali Linux, Exegol, Debian or Ubuntu! Other systems are not yet supported${NC}\n"
    exit 1
fi

# Update repositories
apt-get update

# Install required packages via apt

## Install jq
command -v "jq" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install jq -y
    fi

## Install git
command -v "git" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install git -y
    fi

## Install go
command -v "go" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Exegol" ]; then
            apt-get install gccgo-go -y
            if [ "$OS" = "Kali" ]; then
                export PATH=$PATH:/root/go/bin
            fi
        elif [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            wget https://dl.google.com/go/go1.21.3.linux-amd64.tar.gz
            tar -xvf go1.21.3.linux-amd64.tar.gz
            mv go /usr/local
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            rm -rf go1.21.3.linux-amd64.tar.gz
        fi
    fi

## Install whois
command -v "whois" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install whois -y
    fi

## Install curl
command -v "curl" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install curl -y
    fi

## Install wget
command -v "wget" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install wget -y
    fi

## Install pip2
command -v "pip2" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Ubuntu" ]; then
            apt-get install python2 -y
            wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
            python2 get-pip.py
            rm -rf get-pip.py
            pip2 install hsecscan
        elif [ "$OS" = "Debian" ]; then
            sudo apt-get install build-essential libsqlite3-dev zlib1g-dev libncurses5-dev libgdbm-dev libbz2-dev libssl-dev libdb-dev -y
            wget -c http://ftp.debian.org/debian/pool/main/libf/libffi/libffi7_3.3-6_amd64.deb
            wget -c http://ftp.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb
            wget -c http://ftp.debian.org/debian/pool/main/p/python2.7/libpython2.7-minimal_2.7.18-8+deb11u1_amd64.deb
            wget -c http://ftp.debian.org/debian/pool/main/p/python2.7/python2.7-minimal_2.7.18-8+deb11u1_amd64.deb
            wget -c http://ftp.debian.org/debian/pool/main/p/python2.7/libpython2.7-stdlib_2.7.18-8+deb11u1_amd64.deb
            wget -c http://ftp.debian.org/debian/pool/main/p/python2.7/python2.7_2.7.18-8+deb11u1_amd64.deb
            wget -c https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
            sudo dpkg -i libffi7_3.3-6_amd64.deb libssl1.1_1.1.1w-0+deb11u1_amd64.deb libpython2.7-minimal_2.7.18-8+deb11u1_amd64.deb python2.7-minimal_2.7.18-8+deb11u1_amd64.deb libpython2.7-stdlib_2.7.18-8+deb11u1_amd64.deb python2.7_2.7.18-8+deb11u1_amd64.deb google-chrome-stable_current_amd64.deb
            sudo apt-get -fy install
            rm -rf *.deb
            wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
            python2.7 get-pip.py
            rm -rf *.deb get-pip.py
            pip2 install hsecscan
            sudo apt --fix-broken install -y
            sudo apt-get install python3 python3-pip -y
        else
            wget https://gist.githubusercontent.com/anir0y/a20246e26dcb2ebf1b44a0e1d989f5d1/raw/a9908e5dd147f0b6eb71ec51f9845fafe7fb8a7f/pip2%2520install -O run.sh 
            chmod +x run.sh
            ./run.sh
            rm -rf run.sh
            pip2 install hsecscan
        fi
    fi

## Install nuclei
command -v "nuclei" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install nuclei -y
        elif [ "$OS" = "Debian" ]; then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            mv /root/go/bin/nuclei /usr/bin/
            nuclei -update
            nuclei -ut
        elif [ "$OS" = "Ubuntu" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            mv /root/go/bin/nuclei /usr/bin/
            /usr/bin/nuclei -update
            /usr/bin/nuclei -ut
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            nuclei -update
            nuclei -ut
        fi
    fi

## Install eyewitness
command -v "eyewitness" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install eyewitness -y
        elif [ "$OS" = "Debian" ] || [ "$OS" = "Ubuntu" ]; then
            apt-get install python3-pip -y
            current_dir=$(pwd)
            cd /opt/
            apt-get install -y git python3-pip xvfb libssl-dev libffi-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev wkhtmltopdf
            pip3 install --upgrade setuptools --break-system-packages
            git clone https://github.com/FortyNorthSecurity/EyeWitness.git
            cd EyeWitness/Python/setup
            sed -i -e "s/python3 -m pip install/python3 -m pip install --break-system-packages/g" setup.sh
            bash setup.sh
            cd ..
            sed -i -e "s@\#\!/usr/bin/env python3@\#\!$(which python3)@" EyeWitness.py
            cd $current_dir
            alias eyewitness='/opt/EyeWitness/Python/EyeWitness.py'
            chmod -R 777 /opt/EyeWitness/Python
        fi
    fi

## Install subfinder
command -v "subfinder" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install subfinder -y
        elif [ "$OS" = "Debian" ]; then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            mv /root/go/bin/subfinder /usr/bin/
        elif [ "$OS" = "Ubuntu" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            mv /root/go/bin/subfinder /usr/bin/
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        fi
    else
        if [ "$OS" = "Exegol" ]; then
            subfinder -up
            katana -up
        fi
    fi

## Install SANextract
command -v "SANextract" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        git clone https://github.com/hvs-consulting/SANextract
        current_dir=$(pwd)
        cd SANextract
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ]; then
            export GO111MODULE="on"
            go mod init SANextract
            go build
        elif [ "$OS" = "Debian" ];then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go mod init SANextract
            go build
        else
            go env -w GO111MODULE=off
            go mod init SANextract
            go build
        fi
        chown $(echo "$USER"):$(echo "$USER") SANextract
        mv SANextract /usr/bin/
        cd $current_dir
        rm -rf SANextract
    fi

## Install gowitness
command -v "gowitness" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        wget -c "https://github.com/sensepost/gowitness/releases/download/2.4.2/gowitness-2.4.2-linux-amd64"
        mv gowitness* gowitness
        chmod +x gowitness
        mv gowitness /usr/bin
    fi

## Install webanalyze
command -v "webanalyze" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ]; then
            export GO111MODULE="on"
            go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
            mv /root/go/bin/webanalyze /usr/bin/
        elif [ "$OS" = "Debian" ]; then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
            mv /root/go/bin/webanalyze /usr/bin/
        else
            go env -w GO111MODULE=off
            go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
        fi
        webanalyze -update
    fi

## Install gau
command -v "gau" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install getallurls -y
        elif [ "$OS" = "Ubuntu" ];then
            export GO111MODULE="on"
            go install github.com/lc/gau/v2/cmd/gau@latest
            mv /root/go/bin/gau /usr/bin/
            echo "[[wayback_machines]]" > .gau.toml
            echo 'url = "https://web.archive.org/save/%s"' >> .gau.toml
            for d in /home/*/ ; do
                cp .gau.toml $d/
            done
            mv .gau.toml /root/
        elif [ "$OS" = "Debian" ]; then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go install github.com/lc/gau/v2/cmd/gau@latest
            mv /root/go/bin/gau /usr/bin/
            echo "[[wayback_machines]]" > .gau.toml
            echo 'url = "https://web.archive.org/save/%s"' >> .gau.toml
            for d in /home/*/ ; do
                cp .gau.toml $d/
            done
            mv .gau.toml /root/
        else
            go env -w GO111MODULE=off
            go install github.com/lc/gau/v2/cmd/gau@latest
        fi
    else
        if [ "$OS" = "Exegol" ]; then
            go install github.com/lc/gau/v2/cmd/gau@latest
        fi
    fi

## Install httpmethods
command -v "httpmethods" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        git clone https://github.com/ShutdownRepo/httpmethods
        current_dir=$(pwd)
        chown -R $(echo "$USER"):$(echo "$USER") httpmethods
        cd httpmethods
        rm -rf assets/ wordlists/
        python3 setup.py install
        cd $current_dir
        if [ "$OS" = "Exegol" ]; then
            export PATH=$PATH:/root/.pyenv/versions/3.11.7/bin
            echo "PATH=$PATH:/root/.pyenv/versions/3.11.7/bin" >> ~$(echo "$USER")/.zshrc
        fi
    fi

## Install httpx
command -v "httpx" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            mv /root/go/bin/httpx /usr/bin/
        elif [ "$OS" = "Debian" ]; then
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            mv /root/go/bin/httpx /usr/bin/
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        fi
    else
        if [ "$OS" = "Exegol" ]; then
            httpx -up
        fi
    fi


## Install findomain
command -v "findomain" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
        unzip findomain-linux.zip
        chmod +x findomain
        mv findomain /usr/bin/findomain
        rm -rf findomain-linux.zip
    fi

# Install required packages via pip2 and pip3
if [ "$OS" = "Exegol" ]; then
  /usr/bin/python3 -m pip install aiodnsbrute cidrize alive-progress wafw00f tldextract termcolor --break-system-packages
else
  pip3 install aiodnsbrute cidrize alive-progress wafw00f tldextract termcolor dnsrecon "urllib3<2" --break-system-packages
fi

# Download ssh-audit
if [ ! -d ' /opt/ssh-audit' ]; then
    cd /opt/
    git clone "https://github.com/jtesta/ssh-audit.git"
    chown -R $(echo "$USER"):$(echo "$USER") /opt/ssh-audit
fi

# Download SecLists
if [ ! -d ' /opt/SecLists-DNS' ]; then
    cd /opt/
    mkdir SecLists-DNS
    cd SecLists-DNS
    wget -c https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt
    chown -R $(echo "$USER"):$(echo "$USER") /opt/SecLists-DNS
fi

# Download testssl
if [ ! -d ' /opt/testssl.sh' ]; then
    cd /opt/
    git clone https://github.com/drwetter/testssl.sh.git
    chown -R $(echo "$USER"):$(echo "$USER") /opt/testssl.sh
fi

# Install MSF
command -v "msfconsole" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        sudo apt install gpgv2 autoconf bison build-essential postgresql libaprutil1 libgmp3-dev libpcap-dev openssl libpq-dev libreadline6-dev libsqlite3-dev libssl-dev locate libsvn1 libtool libxml2 libxml2-dev libxslt-dev wget libyaml-dev ncurses-dev  postgresql-contrib xsel zlib1g zlib1g-dev curl -y
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        chmod 755 msfinstall
        ./msfinstall
        rm -rf msfinstall
    fi

# Replace global variables in blackbox_audit.py
## Variable init
cd $initial_dir
httpmethods_location=$(which httpmethods)
if [ "$OS" = "Debian" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Kali" ]; then
    webanalyze_location=$(which webanalyze)
else
    webanalyze_location="$(go env GOPATH)/bin/webanalyze"
fi
if [ "$OS" = "Kali" ]; then
    gau_location=$(which getallurls)
else
    gau_location=$(which gau)
fi

## Actual replacement
old_location="/opt/httpmethods/httpmethods.py"
if [[ $httpmethods_location == *"aliased to"* ]]; then
    httpmethods_location=$(which httpmethods | awk '{print $5}')
fi
sed -i -e "s@$old_location@$httpmethods_location@" blackbox_audit.py
old_location="/usr/bin/webanalyze"
sed -i -e "s@$old_location@$webanalyze_location@" blackbox_audit.py
old_location="/usr/bin/gau"
sed -i -e "s@$old_location@$gau_location@" blackbox_audit.py

# Replace global variables in asset_discovery.py
## Variable init
cd $initial_dir
sanextract_location=$(which SANextract)
if [ "$OS" = "Debian" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Kali" ]; then
    webanalyze_location=$(which webanalyze)
else
    webanalyze_location="$(go env GOPATH)/bin/webanalyze"
fi
if [ "$OS" = "Kali" ]; then
    gau_location=$(which getallurls)
else
    gau_location=$(which gau)
fi
gowitness_location=$(which gowitness)
findomain_location=$(which findomain)
eyewitness_location=$(which eyewitness)

## Actual replacement
old_location="/opt/SANextract/SANextract"
sed -i -e "s@$old_location@$sanextract_location@" asset_discovery.py
old_location="/usr/bin/webanalyze"
sed -i -e "s@$old_location@$webanalyze_location@" asset_discovery.py
old_location="/usr/bin/gau"
sed -i -e "s@$old_location@$gau_location@" asset_discovery.py
old_location="/usr/bin/gowitness"
sed -i -e "s@$old_location@$gowitness_location@" asset_discovery.py
old_location="/usr/bin/findomain"
sed -i -e "s@$old_location@$findomain_location@" asset_discovery.py
old_location="/usr/bin/eyewitness"
if [ "$OS" = "Debian" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Exegol" ]; then
    eyewitness_location="/opt/EyeWitness/Python/EyeWitness.py"
    sed -i -e "s@$old_location@$eyewitness_location@" asset_discovery.py
    if [ "$OS" = "Exegol" ]; then
        apt-get install python3-pip -y
        current_dir=$(pwd)
        cd /opt/
        apt-get install -y git python3-pip xvfb libssl-dev libffi-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev wkhtmltopdf
        pip3 install --upgrade setuptools --break-system-packages
        git clone https://github.com/FortyNorthSecurity/EyeWitness.git
        cd EyeWitness/Python/setup
        sed -i -e "s/python3 -m pip install/python3 -m pip install --break-system-packages/g" setup.sh
        ./setup.sh
        cd ..
        sed -i -e "s@\#\!/usr/bin/env python3@\#\!$(which python3)@" EyeWitness.py
        cd $current_dir
        alias eyewitness='/opt/EyeWitness/Python/EyeWitness.py'
        chmod -R 777 /opt/EyeWitness/Python
    fi
else
    sed -i -e "s@$old_location@$eyewitness_location@" asset_discovery.py
fi

# Move scripts to /usr/bin/
cd $initial_dir
mv blackbox_audit.py /usr/bin/
chmod +x /usr/bin/blackbox_audit.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/blackbox_audit.py
mv asset_discovery.py /usr/bin/
chmod +x /usr/bin/asset_discovery.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/asset_discovery.py

if [ "$OS" = "Exegol" ]; then
    exec zsh
fi

# Cleanup temporary files
sudo apt clean -y && apt autoclean -y
go clean --cache
pip cache purge
