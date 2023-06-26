#!/bin/bash
sudo apt-get update

sudo apt-get install -y wget curl whois xdg-utils golang-go gccgo-go perl whois
pip install droopescan

# Download and install wpscan
sudo apt install ruby-full -y
gem install wpscan

# Download and install nikto
sudo apt install nikto -y

# Download and install ffuf
wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
source ~/.profile
go install github.com/ffuf/ffuf/v2@latest

# Download and install sslyze
pip install --upgrade pip setuptools wheel
pip install --upgrade sslyze

# Download and install joomscan
sudo apt install libwww-perl liblwp-protocol-https-perl -y
sudo apt install git -y
git clone https://github.com/rezasp/joomscan.git
cd joomscan
chmod +x joomscan.pl
sudo ln -s $(pwd)/joomscan.pl /usr/local/bin/joomscan

# Download and install nmap
sudo apt install nmap -y

# Download and install Node.js and NPM
sudo apt install nodejs -y

# Download and install solc-selct
pip install solc-select
solc-select install "$(solc-select install | tail -n 1)" > version && solc-select install "$(cat version)"
solc-select install "$(solc-select install | tail -n 1)" > version && solc-select use "$(cat version)"


echo "[+] All tools downloaded and installed successfully!"
