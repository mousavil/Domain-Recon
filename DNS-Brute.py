#!usr/bin/env python3

# modules
import os,sys
import motor.motor_asyncio as mongo
import subprocess
import aiofiles
import json
from os import path
import argparse
from multiprocessing import Process

# initiate
processes = []
DB_USERNAME = "amir"
DB_PASSWORD = "Am0925227307"
class Domain(object):
    def __init__(self):
        self.name = ''


parser = argparse.ArgumentParser(description='Subfinder(By Mousavil)')
parser.add_argument('-d', "--domain", help="Target Domain",
                    required=True)
parser.add_argument('-af', "--use-assetfinder", help="To Use Assetfinder Tool",
                    action="store_true", dest="use_assetfinder",required=False)
parser.add_argument('-sf', "--use-subfinder", help="To Use Subfinder Tool",
                    action="store_true", dest="use_subfinder",required=False)
parser.add_argument('-sl', "--use-sublist3r", help="To Use Sublist3r Tool",
                    action="store_true", dest="use_sublist3r",required=False)
parser.add_argument('-fd', "--use-findomain", help="To Use Findomain Tool",
                    action="store_true", dest="use_findomain",required=False)
parser.add_argument('-crt', "--use-certsh-api", help="To Use cert.sh API",
                    action="store_true", dest="use_certsh_api",required=False)
parser.add_argument('-aip', "--use-abuseip-api", help="To Use AbuseIP API",
                    action="store_true", dest="use_abuseip_api",required=False)
parser.add_argument('-c', "--config",
                    help="You Can Use Config File Instead; With Extra Options. If Config With Argument Are Passed, Config File Will Only Be Used ",
                    action="store_const",required=False)

def check_thread_running(threads):
    return True in [t.is_alive() for t in threads]


async def validate_file(file_path:str):
    return path.isfile(file_path)


async def call_subfinder(domain: str):
    subfinder = subprocess.Popen("subfinder -d " + domain, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = subfinder.communicate()
    subfinder_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            subfinder_output.append(line)
    return subfinder_output


async def call_sublist3r(domain: str):
    sublist3r = subprocess.Popen("sublist3r -d " + domain, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = sublist3r.communicate()
    sublist3r_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            sublist3r_output.append(line)
    return sublist3r_output


async def call_findomain(domain: str):
    findomain = subprocess.Popen("findomain-linux --target " + domain, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = findomain.communicate()
    findomain_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            findomain_output.append(line)


async def call_assetfinder(domain: str):
    assetfinder = subprocess.Popen("assetfinder --subs-only " + domain, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = assetfinder.communicate()
    assetfinder_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            assetfinder_output.append(line)


async def call_certsh(domain: str):
    certsh = subprocess.Popen(
        'curl -sk "https://crt.sh/?q=' + domain + '&output=json" | jq -r ".[].common_name,.[].name_value" | deduplicate --sort >> DB-DNS-Brute/API_crt-sh.txt',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = certsh.communicate()
    certsh_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            certsh_output.append(line)


async def call_abuse_ip(domain: str):
    abuse_ip = subprocess.Popen(
        '''curl -s "https://www.abuseipdb.com/whois/''' + domain + '''" -H "user-agent: Chrome" | grep -E "<li>\w.*</li>" | sed -E "s/<\/?li>//g" | sed -e "s/$/.''' + domain + '''/" >> DB-DNS-Brute/API_abuseipdb.txt''',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = abuse_ip.communicate()
    abuse_ip_output = []
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            abuse_ip_output.append(line)





try:
    args = vars(parser.parse_args())
except:
    exit(0)

if (not (args.use_assetfinder or args.use_subfinder or args.use_sublist3r or \
         args.use_findomain or args.use_abuseip_api or args.config)) or not args.domain:
    print('Wrong Argument Passing!')
    sys.exit()

use_assetfinder, use_subfinder, use_sublist3r, use_findomain, use_abuseip_api, config_path = args.use_assetfinder, args.use_subfinder, args.use_sublist3r, args.use_findomain, args.use_abuseip_api, args.config
domain=Domain()
domain.name=args.domain

if config_path:
    await validate_file(config_path)
    async with aiofiles.open(config_path, mode='r') as f:
        config=json.load(f)
        use_assetfinder=config['use-assetfinder']
        use_subfinder=config['use-subfinder']
        use_sublist3r=config['use-sublist3r']
        use_findomain=config['use-findomain']
        use_abuseip_api=config['use-abuseip-api']

def add_process(function,domain):
    proc = Process(target=function, args=(domain.name))
    processes.append(proc)
    proc.start()
    try:
        add_process(call_assetfinder,)
        if use_assetfinder:
            proc = Process(target=call_assetfinder, args=(domain.name))
            processes.append(proc)
            proc.start()
        
        use_subfinder, use_sublist3r, use_findomain, use_abuseip_api

    for thread in threads:
        thread.start()
    while check_thread_running(threads):
        time.sleep(0)
    except KeyboardInterrupt:
        pass
    finally:
        maxDelay=max( max(pong.delays) for pong in pongs)

# path1 = "/root/**script path***/dns_brute"
# path2 = "/root/**script path***/dns_brute/DB-DNS-Brute"


# remove soon
# os.system('rm -r DB-DNS-Brute')
# db connection setup
client = mongo.AsyncIOMotorClient(
    f'mongodb+srv://{DB_USERNAME}:{DB_PASSWORD}@127.0.0.1/admin?retryWrites=true&w=majority')
db = client[domain.name]
collection = db.subdomains
# remove soon
# domain_path = domain.name.replace(".","-")
# os.chdir(path1)
# os.system('mkdir DB-DNS-Brute')
# os.system('mkdir DB-DNS-Resolve')
# os.system('mkdir DB-DNS-Resolve/' + domain_path)

# Get Resolver
# https://github.com/BonJarber/fresh-resolvers
os.system('rm -f resolvers.txt')
os.system('wget https://github.com/BonJarber/fresh-resolvers/blob/main/resolvers.txt')

# ---------Tools----------
subfinder_output =await call_subfinder(domain.name)
# os.system("subfinder -d " + domain.name + " -o DB-DNS-Brute/Tools_Subfinder.txt")
sublist3r_output =await call_sublist3r(domain.name)
# os.system("sublist3r -d " + domain.name + " -o DB-DNS-Brute/Tools_Sublist3r.txt")
findomain_output= await call_findomain(domain.name)
# os.system("findomain-linux --output --target " + domain.name)
# os.system("mv " + domain.name + ".txt DB-DNS-Brute/Tools_findomain.txt")
assetfinder_output= await call_assetfinder(domain.name)
# os.system('assetfinder --subs-only ' + domain.name + ' >> DB-DNS-Brute/Tools_assetfinder.txt')


# ---------APIS----------

# CRT.SH
certsh_output = await call_certsh(domain.name)
# os.system('curl -sk "https://crt.sh/?q=' + domain.name + '&output=json" | jq -r ".[].common_name,.[].name_value" | deduplicate --sort >> DB-DNS-Brute/API_crt-sh.txt')
abuse_ip_output = await call_abuse_ip(domain.name)
# os.system('''curl -s "https://www.abuseipdb.com/whois/'''+ domain.name +'''" -H "user-agent: Chrome" | grep -E "<li>\w.*</li>" | sed -E "s/<\/?li>//g" | sed -e "s/$/.'''+ domain.name +'''/" >> DB-DNS-Brute/API_abuseipdb.txt''')


# ---------------------
# remove soon
# os.chdir(path2)
# Merge Subdomains
merged_subdomains = list(
    set(abuse_ip_output + certsh_output + assetfinder_output + findomain_output + sublist3r_output + subfinder_output))
# os.system("cat Tools_Subfinder.txt Tools_Sublist3r.txt Tools_findomain.txt Tools_assetfinder.txt API_crt-sh.txt API_abuseipdb.txt >> Merge_subdomains.txt")

# Remove Duplicate
# os.system('cat Merge_subdomains.txt | deduplicate --sort >> no_duplicate.txt')
# ---------------------


if domain.generate_worldlist:

    # Bind Wordlist with domain --> <wordlist>.domain.tld
    # remove soon
    # os.chdir(path1)
    # os.system('cp wordlists/wordlist_1.txt DB-DNS-Brute/Bind_domain_wordlist.txt')
    # os.system("sed -e 's/$/." + domain.name + "/' -i DB-DNS-Brute/Bind_domain_wordlist.txt")
    # print('[+] Generate Wordlist.' + domain.name + ' Ok\n')

    os.system('mkdir ./' + domain.name)
    os.system('cp wordlists/wordlist_1.txt ./' + domain.name + '/bind_domain.txt')
    generated_subdomains = subprocess.Popen(
        "sed -e 's/$/." + domain.name + "/' -i ./" + domain.name + '/bind_domain.txt', stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    out, err = generated_subdomains.communicate()
    async with aiofiles.open('filename', mode='r') as f:
        async for line in f:
            print(line)

    # Merge Wordlist.domain.tld with Provider
    os.system(
        'cat DB-DNS-Brute/no_duplicate.txt DB-DNS-Brute/Bind_domain_wordlist.txt | sort -u >> DB-DNS-Brute/Merge_subdomains_2.txt')

    # shuffledns-step1
    os.system(
        'shuffledns -d ' + domain.name + ' -list DB-DNS-Brute/Merge_subdomains_2.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_1.txt')

    # DNSGen
    os.system(
        'cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/no_duplicate.txt | sort -u | dnsgen - >> DB-DNS-Brute/dnsgen.txt')

    # shuffledns-step2
    os.system(
        'shuffledns -d ' + domain.name + ' -list DB-DNS-Brute/dnsgen.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_2.txt')

    # Merge_Resolved
    os.system(
        'cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/Resolve_2.txt | sort -u >> DB-DNS-Resolve/' + domain_path + '/' + domain_path + '.txt')

# Send END Notify
# os.system("echo  'DNS-Brute(" + domain +  ") -->  END' | notify -id '***'")
