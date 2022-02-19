#!usr/bin/env python3
import os
import sys

domain_input = sys.argv[1]
domain_path = domain_input.replace(".","-")
os.system('rm -r DB-DNS-Brute')

#Send Start Notify
#os.system("echo  'DNS-Brute(" + domain_input +  ") -->  END' | notify -id '***'")

path1 = "/root/**script path***/dns_brute"
path2 = "/root/**script path***/dns_brute/DB-DNS-Brute"

os.chdir(path1)
os.system('mkdir DB-DNS-Brute')
os.system('mkdir DB-DNS-Resolve')
os.system('mkdir DB-DNS-Resolve/' + domain_path)

#Get Resolver
#https://github.com/BonJarber/fresh-resolvers
os.system('rm -f resolvers.txt')
os.system('wget https://github.com/BonJarber/fresh-resolvers/blob/main/resolvers.txt')

#---------Tools----------
#Subfinder
os.system("subfinder -d " + domain_input + " -o DB-DNS-Brute/Tools_Subfinder.txt")

#Sublist3r
os.system("sublist3r -d " + domain_input + " -o DB-DNS-Brute/Tools_Sublist3r.txt")

#findomain-linux
os.system("findomain-linux --output --target " + domain_input)
os.system("mv " + domain_input + ".txt DB-DNS-Brute/Tools_findomain.txt")

#Assetfinder
os.system('assetfinder --subs-only ' + domain_input + ' >> DB-DNS-Brute/Tools_assetfinder.txt')


#---------API----------

#CRT.SH
os.system('curl -sk "https://crt.sh/?q=' + domain_input + '&output=json" | jq -r ".[].common_name,.[].name_value" | deduplicate --sort >> DB-DNS-Brute/API_crt-sh.txt')

#AbuseIP
os.system('''curl -s "https://www.abuseipdb.com/whois/'''+ domain_input +'''" -H "user-agent: Chrome" | grep -E "<li>\w.*</li>" | sed -E "s/<\/?li>//g" | sed -e "s/$/.'''+ domain_input +'''/" >> DB-DNS-Brute/API_abuseipdb.txt''')


#---------------------
os.chdir(path2)
#Merge Subdomains
os.system("cat Tools_Subfinder.txt Tools_Sublist3r.txt Tools_findomain.txt Tools_assetfinder.txt API_crt-sh.txt API_abuseipdb.txt >> Merge_subdomains.txt")

#Remove Duplicate
os.system('cat Merge_subdomains.txt | deduplicate --sort >> no_duplicate.txt')
#---------------------
#Bind Wordlist with domain --> <wordlist>.domain.tld
os.chdir(path1)

os.system('cp wordlists/wordlist_1.txt DB-DNS-Brute/Bind_domain_wordlist.txt')
os.system("sed -e 's/$/." + domain_input + "/' -i DB-DNS-Brute/Bind_domain_wordlist.txt")
print('[+] Generate Wordlist.' + domain_input + ' Ok\n')

#Merge Wordlist.domain.tld with Provider
os.system('cat DB-DNS-Brute/no_duplicate.txt DB-DNS-Brute/Bind_domain_wordlist.txt | sort -u >> DB-DNS-Brute/Merge_subdomains_2.txt')

#shuffledns-step1
os.system('shuffledns -d ' + domain_input + ' -list DB-DNS-Brute/Merge_subdomains_2.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_1.txt')

#DNSGen
os.system('cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/no_duplicate.txt | sort -u | dnsgen - >> DB-DNS-Brute/dnsgen.txt')

#shuffledns-step2
os.system('shuffledns -d ' + domain_input + ' -list DB-DNS-Brute/dnsgen.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_2.txt')

#Merge_Resolved
os.system('cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/Resolve_2.txt | sort -u >> DB-DNS-Resolve/' + domain_path + '/' + domain_path + '.txt')

#Send END Notify
#os.system("echo  'DNS-Brute(" + domain_input +  ") -->  END' | notify -id '***'")
