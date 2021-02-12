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
#		- add nmap, crtsh, altdns, massdns
#		- add cronjob & telebot notification
#		- byakugan will become powerful from time to time!
#		- xss snap with aquatone or eyewitness then verify alive subdo n try hunt xss
#
#	3. Ongoing 
#		- Implementing nuclei functions [DONE]
#		- implement clean gau result
#		- implement Open Redirect
#
#	4. todo#		
#		- compare paramspider and wayback + gau result
#		- use openredireX 
#		- Update output file
#		- implement githound
#		- for dir bruteforce https://github.com/dark-warlord14/ffufplus/blob/master/script.sh
#		- for active n passive enum https://github.com/remonsec/SEF/blob/5697616dc7a26051ea124d99994a9bc854bc9fdd/sef
#
#	5. Change
#		- JSScanner manually
#		- githound manually
#		- sef manually
#
#
#
###########################################################################

VERSION="3.0"

TARGETS=$1
OUTPUT=$2

dir_wordlist=~/byakugan/wordlist/dict.txt
param_wordlist=~/byakugan/wordlist/param.txt
vhost_wordlist=~/byakugan/wordlist/vhost.txt
lfi_wordlist=~/byakugan/wordlist/lfi_wordlist.txt

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
    echo -e "${YELLOW}[+] $1 ${RESET}"
}

log(){
    echo -e "\n${GREEN}[*] $1 ${RESET}\n"
}

subdomain(){

#==============================Collecting Subdomains and checking for takeovers=======================================

 	log "Starting subdomains collection $TARGET"	

        status "amass"
        amass enum -passive -norecursive -noalts -d $TARGET -o $TARGET_PATH/amass.tmp		 	

        status "Running Sublist3r"
	python /root/tools/Sublist3r/sublist3r.py -d $TARGET -o $TARGET_PATH/subdo.tmp      

        status "Running Assetfinder"
        assetfinder --subs-only $TARGET | tee -a $TARGET_PATH/subdo.tmp

        status "Running Subfinder"
        subfinder -d $TARGET -t 100 -nW -silent | tee -a $TARGET_PATH/subdo.tmp

	status "Running Findomain"
	findomain --quiet -t $TARGET -u $TARGET_PATH/findomain.tmp

	status "Running Crobat"
	crobat -s $TARGET | anew -q $TARGET_PATH/crobat.tmp

        cat $TARGET_PATH/*.tmp | cut -d"/" -f 3 | sort -u -o $TARGET_PATH/subdo.txt    
	rm $TARGET_PATH/*.tmp 

	log "Checking for Subdomain Takeover Scan"

        status "Running subjack"
        subjack -w $TARGET_PATH/subdo.txt -t 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 | tee -a $TARGET_PATH/subjack.tmp
	cat $TARGET_PATH/subjack.tmp | grep -v "Not Vulnerable" >> $WORKING_DIR/vuln-$OUTPUT-$todate.txt	
	rm $TARGET_PATH/subjack.tmp

        status "Running subzy"
        subzy -targets $TARGET_PATH/subdo.txt -hide_fails --verify_ssl -concurrency 20 | sort -u |tee -a $TARGET_PATH/subzy.txt
	cat $TARGET_PATH/subzy.txt | grep VULNERABLE >> $WORKING_DIR/vuln-$OUTPUT-$todate.txt

        status "Running nuclei"
	cat $TARGET_PATH/subdo.txt | nuclei -silent -t ~/nuclei-templates/subdomain-takeover/detect-all-takeovers.yaml -o $TARGET_PATH/nuclei_sto.txt	
	

}

portscan(){
#==============================Port Scanning=======================================
	log "Port Scanning initiated"
	#check doc again
	#status "Check host list"

	status "Running Naabu"
	cat $TARGET_PATH/subdo.txt | naabu -top-ports 1000 -silent -exclude-cdn -nmap-cli 'nmap -sV --script /usr/share/nmap/scripts/vulners.nse,http-title.nse --min-rate 40000 -T4 --max-retries 2' -o $TARGET_PATH/naabu.txt
	#naabu -top-ports 1000 -silent -exclude-cdn -nmap-cli 'nmap -sV --script /usr/share/nmap/scripts/vulners.nse,http-title.nse --min-rate 40000 -T4 --max-retries 2' -o $TARGET_PATH/naabu.txt
	#naabu -ports - -exclude-ports 80,443 -silent -iL $TARGET_PATH/subdo.txt -o $TARGET_PATH/naabu.txt

}

getAlive(){
#==============================Collecting alive url=======================================
	log "Collecting alive url only"

	#probing
	status "Running httprobe"
	cat $TARGET_PATH/subdo.txt | httprobe -c 100 > $TARGET_PATH/alives.tmp
	status "Running httpx"
	cat $TARGET_PATH/subdo.txt | httpx -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' >> $TARGET_PATH/alives.tmp
	status "Running httpx for uncommon port"
	cat $TARGET_PATH/subdo.txt | httpx -ports 81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55672 -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' >> $TARGET_PATH/alives.tmp
	status "Merging.."
	sort -u $TARGET_PATH/alives.tmp -o $TARGET_PATH/alives.txt
	rm $TARGET_PATH/alives.tmp
	status "Done merge and sort unique"
	
	#url extract
	status "Running waybackurls" 
	cat $TARGET_PATH/alives.txt | waybackurls > $TARGET_PATH/urls.tmp
	status "Running gau"
	cat $TARGET_PATH/alives.txt | gau | anew -q >> $TARGET_PATH/urls.tmp
	status "Running hakrawler"
	hakrawler -url $TARGET -depth 2 -scope subs -plain -insecure | anew -q $TARGET_PATH/urls.tmp

	status "Merging.."
	sort -u $TARGET_PATH/urls.tmp -o $TARGET_PATH/urls.txt
	rm $TARGET_PATH/urls.tmp
	status "Done merge and sort unique"

}


getDir(){
#==============================Directory bruteforce=======================================
	log "Directory Bruteforce is onzeway"

	mkdir -p $TARGET_PATH/fuzz
	status "Running FFUF"
    	
	for sub in $(cat $TARGET_PATH/alives.txt); do
		sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
		ffuf -mc all -c -u $sub/FUZZ -w $dir_wordlist -maxtime 900 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -o $TARGET_PATH/fuzz/${sub_out}.tmp
		cat $TARGET_PATH/fuzz/${sub_out}.tmp | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' > $TARGET_PATH/fuzz/${sub_out}_result_dir.txt 
	done

	#interlace -tL $TARGET_PATH/alives.txt -o $TARGET_PATH/fuzz -threads 5 -c "ffuf -mc all -c -u _target_/FUZZ -w $dir_wordlist -maxtime 900 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -o _output_/_target_-result_dir.tmp"
	#for fuzzed in $TARGET_PATH/fuzz; do
	#cat $TARGET_PATH/${sub}-result_dir.tmp | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' > $TARGET_PATH/${sub}_result_dir.txt     

#interlace -tL /root/byakugan/finefriends.social-14-01-2021/min.txt -o /root/byakugan/finefriends.social-14-01-2021/fuzz -threads 5 -c "ffuf -mc all -c -u _target_/FUZZ -w ~/byakugan/wordlist/dicc.txt -maxtime 900 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -od _output_ -o _target_-result_dir.tmp"

#ffuf -mc all -c -u http://hackycorp.com/FUZZ -w ~/byakugan/wordlist/dict.txt -maxtime 900 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -o http://hackycorp.com_result_dir.tmp

#interlace -tL /root/byakugan/msia/ump.edu.my-24-09-2020/min.txt -threads 5 -c "ffuf -mc all -ac -w ~/byakugan/wordlist/dicc.txt -maxtime 900 -u _target_/FUZZ -or -o _target_ffuf.txt &>/dev/null" &>/dev/null
}

nucleiPlz(){
#==============================Using nuclei templates=======================================
	log "nuclei in action"

	status "Running All those mfs templates"
	mkdir -p $TARGET_PATH/nuclei	

	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/technologies/ -o  $TARGET_PATH/nuclei/nuclei_technologies.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o  $TARGET_PATH/nuclei/nuclei_exposed-tokens.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/exposures/ -o  $TARGET_PATH/nuclei/nuclei_exposures.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/generic-detections/ -o  $TARGET_PATH/nuclei/nuclei_generic-detections.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/cves/ -o  $TARGET_PATH/nuclei/nuclei_cves.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/default-logins/ -o  $TARGET_PATH/nuclei/nuclei_default-creds.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/dns/ -o  $TARGET_PATH/nuclei/nuclei_dns.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/files/ -o  $TARGET_PATH/nuclei/nuclei_files.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/exposed-panels/ -o  $TARGET_PATH/nuclei/nuclei_panels.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/misconfiguration/ -o  $TARGET_PATH/nuclei/nuclei_sec-misconf.txt
	cat $TARGET_PATH/alives.txt | nuclei -silent -t ~/nuclei-templates/vulnerabilities/ -o  $TARGET_PATH/nuclei/nuclei_vulns-check.txt

}

gfPatterns(){
#==============================Checking for patterns=======================================
	log "Pattern search initiated"
	
	status "Running gf patterns"
	mkdir -p $TARGET_PATH/gf

	cat $TARGET_PATH/urls.txt | gf xss | anew -q $TARGET_PATH/gf/xss.txt
	cat $TARGET_PATH/urls.txt | gf ssrf | anew -q $TARGET_PATH/gf/ssrf.txt
	cat $TARGET_PATH/urls.txt | gf ssti | anew -q $TARGET_PATH/gf/ssti.txt
	cat $TARGET_PATH/urls.txt | gf sqli | anew -q $TARGET_PATH/gf/sqli.txt
	cat $TARGET_PATH/urls.txt | gf rce | anew -q $TARGET_PATH/gf/rce.txt
	cat $TARGET_PATH/urls.txt | gf lfi | anew -q $TARGET_PATH/gf/lfi.txt
	cat $TARGET_PATH/urls.txt | gf redirect | anew -q $TARGET_PATH/gf/redirect.txt
	cat $TARGET_PATH/urls.txt | gf potential | anew -q $TARGET_PATH/gf/potential.txt

}

favicon(){
#==============================favicon hash=======================================
	log "Pattern search initiated"
	
	status "Running favUp"
	python3 /root/tools/fav-up/favUp.py -w $TARGET_PATH/alives.txt -sc -o $TARGET_PATH/faviconhash.txt
}


cors(){
#==============================CORS Scanning=======================================
	log "CORS scanning initiated"
	
	status "Running Corsy"
	corsy -i $TARGET_PATH/alives.txt -t 200 > $TARGET_PATH/cors.txt

}

cmsScan(){
#==============================CMS Scanning=======================================
	log "CMS scanning initiated"	

	status "Running CMSeeK"

	mkdir -p $TARGET_PATH/cms
	tr '\n' ',' < $TARGET_PATH/alives > $TARGET_PATH/cms/cms.txt
	cmseek -l $TARGET_PATH/cms/cms.txt --batch -r 
	
	for sub in $(cat $TARGET_PATH/alives.txt); do
		sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
		cms_id=$(cat /root/tools/CMSeeK/Result/${sub_out}/cms.json | jq -r '.cms_id')

		if [ -z "$cms_id" ]
		then
			rm -rf /root/tools/CMSeeK/Result/${sub_out}
		else
			mv -f /root/tools/CMSeeK/Result/${sub_out} $TARGET_PATH/cms/
		fi
	done
	
}


crlfScan(){
#==============================CRLF Scanning=======================================
	log "CRLF check initiated"	

	status "Running crlfuzz"	
	crlfuzz -l $TARGET_PATH/alives.txt -o $TARGET_PATH/crlf.txt

}

lfimein(){
#==============================LFI Scanning=======================================	
	log "LFI scan initiated"

	status "Running ffuf for lfi"
	for url in $(cat $TARGET_PATH/gf/lfi.txt); do
		ffuf -v -mc 200 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -w $lfi_wordlist -u $url -mr "root:" | grep "URL" | sed 's/| URL | //' | anew -q $TARGET_PATH/lfi.txt
	done

}


#jsCollector(){
#==============================Collecting .Js files=======================================

	#log "Collecting .Js files"
		
	#status "Running JSScanner"
	#jsscanner $TARGET_PATH/alives.txt
	
	#cat $TARGET_PATH/urls.txt| subjs | anew | tee -a $TARGET_PATH/js.tmp
	
	#cat $TARGET_PATH/urls.txt | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javasxcript' | tee -a $TARGET_PATH/js.tmp

        #sort -u $TARGET_PATH/js.tmp -o $TARGET_PATH/js.txt    
	#rm $TARGET_PATH/js.tmp	
#}

aquasnap(){
#==============================Screenshotszz=======================================
	status "Running Aquatone"
	cat $TARGET_PATH/alives.txt | ~/go/bin/aquatone -chrome-path /usr/bin/chromium -http-timeout 10000 -scan-timeout 300 -ports xlarge -out $TARGET_PATH/snapss
	
}


main(){
while read line; do
	TARGET=$line
	TARGET_PATH="$WORKING_DIR/$TARGET-$todate"
	mkdir -p $TARGET_PATH
	log "$TARGET file created!"

	subdomain
	portscan		
	getAlive
	getDir
	nucleiPlz
	gfPatterns
	cors
	cmscan
	crlfScan
	lfimein
	aquasnap
	#favicon
	#jsCollector	

done < $TARGETS

}

logo
main
