#!/bin/bash

###########################################################################
#
# Change log [last edit on Mon 14/9/2020 8:23 PM]
#	1. Completed v1.0
#		- Read domains from txt file and perform recon & subdoTakeover check
#		- Created unique file for each target and save subdomains and STO result
#		- Tools used (Recon): Amass, sublist3r, subfinder, assetfinder
#		- Tools used (STO): subjack, subzy
#	2. Upcoming update
#		- combine recon tools with amass lua script
#		- add nmap, crtsh, altdns, massdns, aquatone, waybackurl
#		- add cronjob & telebot notification
#		- byakugan will become powerful from time to time!
#
###########################################################################

TARGETS=$1

VERSION="1.0"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

WORKING_DIR=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

todate=$(date +"%d-%m-%Y")

logo(){
echo -e "${BLUE}
   ___             _                            
  / __\_   _  __ _| | ___   _  __ _  __ _ _ __  
 /__\// | | |/ _  | |/ / | | |/ _  |/ _  |  _ \ 
/ \/  \ |_| | (_| |   <| |_| | (_| | (_| | | | |
\_____/\__, |\__,_|_|\_\___,_|\__, |\__,_|_| |_| 
       |___/                  |___/             
				            ${RED}v$VERSION${RESET} 
			 	    by ${YELLOW}@0xAzrael${RESET}
	    A recon tool untuk scan hati manusia"
}

setupDir(){
    echo -e "${GREEN}[*] Setting up directory for $line ${RESET}"
    mkdir -p $TARGET_PATH-$todate
    echo -e "${BLUE}[*] File for $TARGET_PATH created! ${RESET}"

}

status(){
    echo -e "${YELLOW}\n[+] $1 ${RESET}"
}

log(){
    echo -e "${GREEN}[*] $1 ${RESET}"
}

main(){
while read line; do
	TARGET=$line
	TARGET_PATH="$WORKING_DIR/$TARGET-$todate"
	mkdir $TARGET_PATH
	log "$TARGET file created!"
 	log "Starting Recon & SubdoTakeover on $TARGET"	

        status "Running Sublist3r"
	python /root/tools/Sublist3r/sublist3r.py -d $TARGET -o $TARGET_PATH/subdo.tmp      

        status "Running Assetfinder"
        assetfinder --subs-only $TARGET |tee -a $TARGET_PATH/subdo.tmp

        status "Running subfinder"
        subfinder -d $TARGET -t 100 -nW -silent |tee -a $TARGET_PATH/subdo.tmp

        #status "amass"
        #amass enum -d $TARGET | tee -a $TARGET_PATH/subdo.tmp	
	
        sort -u $TARGET_PATH/subdo.tmp -o $TARGET_PATH/subdo.txt    
	rm $TARGET_PATH/subdo.tmp

	log "Starting Subdomain Takeover Scan"

        status "Running subjack"
        subjack -w $TARGET_PATH/subdo.txt -t 20 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $TARGET_PATH/subjack.txt

        status "Running subzy"
        subzy -targets $TARGET_PATH/subdo.txt -hide_fails --verify_ssl -concurrency 20 | sort -u |tee -a $TARGET_PATH/subzy.txt
	
	log "DONE!"	

done < $TARGETS

}

logo
main
