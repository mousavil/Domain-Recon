#!usr/bin/env python3

# Modules
import os,sys
import motor.motor_asyncio as mongo
import subprocess
import aiofiles
import json
from os import path
import argparse
from multiprocessing import Process,Queue
import asyncio



# Initiates
processes = []
subdomains = []
DB_USERNAME = "amir"
DB_PASSWORD = "Am0925227307"
class Domain(object):
    def __init__(self):
        self.name = ''

#Functions

def validate_file(file_path:str):
    return path.isfile(file_path)


def call_subfinder(domain: str,q:Queue):
    try:
        # subfinder = subprocess.Popen(["subfinder", "-d", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # out, err = subfinder.communicate()
        # for line in out.decode('utf-8').split('\n'):
        #     if domain in line:
        q.put("line1")
        q.put('Done')
    except Exception as e:        
        file=open('/home/amirmousavi/Desktop/projects/dns-brute/test1.txt','w')
        file.write(str(e))
        file.close()

def call_sublist3r(domain: str,q:Queue):
    # sublist3r = subprocess.Popen(["sublist3r", "-d", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # out, err = sublist3r.communicate()
    # for line in out.decode('utf-8').split('\n'):
    #     if domain in line:
    #         q.put(line)
    q.put("line2")
    q.put('Done')

def call_findomain(domain: str,q:Queue):
    findomain = subprocess.Popen(["findomain-linux" ,"--target", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = findomain.communicate()
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            q.put(line)
    q.put('Done')

def call_assetfinder(domain: str,q:Queue):
    assetfinder = subprocess.Popen(["assetfinder", "--subs-only", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = assetfinder.communicate()
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            q.put(line)
    q.put('Done')
    
def call_certsh(domain: str,q:Queue):
    certsh = subprocess.Popen(
        'curl -sk "https://crt.sh/?q=' + domain + '&output=json" | jq -r ".[].common_name,.[].name_value" | deduplicate --sort >> DB-DNS-Brute/API_crt-sh.txt',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = certsh.communicate()
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            q.put(line)
    q.put('Done')

def call_abuse_ip(domain: str,q:Queue):
    abuse_ip = subprocess.Popen(
        '''curl -s "https://www.abuseipdb.com/whois/''' + domain + '''" -H "user-agent: Chrome" | grep -E "<li>\w.*</li>" | sed -E "s/<\/?li>//g" | sed -e "s/$/.''' + domain + '''/" >> DB-DNS-Brute/API_abuseipdb.txt''',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = abuse_ip.communicate()
    for line in out.decode('utf-8').split('\n'):
        if domain in line:
            q.put(line)
    q.put('Done')

def add_process(function,domain,q):
    global processes
    proc = Process(target=function, args=(domain,q,))
    processes.append(proc)
    proc.start()

def join_process(proc: Process):
    if proc is not None:
        proc.join()

def append_subdomains(q:Queue):
    global subdomains
    while True:
        sub= q.get()
        if sub == 'Done' or sub == None:
            break
        subdomains.append(sub)

#Main Function

async def main():
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
    parser.add_argument('-m', "--diff", help="Get Only New Subdomains",
                        action="store_true", dest="return_diffrences")
    parser.add_argument('-c', "--config",
                        help="You Can Use Config File Instead; With Extra Options. If Config With Argument Are Passed, Config File Will Only Be Used ",
                        dest="config",required=False)


    try:
        args = vars(parser.parse_args())
    except:
        exit(0)

    if (not (args['use_assetfinder'] or args['use_subfinder'] or args['use_sublist3r'] or \
            args['use_findomain'] or args['use_abuseip_api'] or args['config'])) or not args['domain']:
        print('Wrong Argument Passing!')
        sys.exit()

    use_assetfinder, use_subfinder, use_sublist3r, use_findomain,use_certsh_api, use_abuseip_api, config_path,return_diffrences = args['use_assetfinder'], args['use_subfinder'], args['use_sublist3r'], args['use_findomain'],args['use_certsh_api'], args['use_abuseip_api'], args['config'],args['return_diffrences']
    domain=Domain()
    domain.name=args['domain']

    if config_path:
        await validate_file(config_path)
        async with aiofiles.open(config_path, mode='r') as f:
            config=json.load(f)
            use_assetfinder=config['use-assetfinder']
            use_subfinder=config['use-subfinder']
            use_sublist3r=config['use-sublist3r']
            use_findomain=config['use-findomain']
            use_abuseip_api=config['use-abuseip-api']
            use_certsh_api=config['use-certsh-api']
            return_diffrences=config['return-diffrences']


    try:
        q1=Queue();q2=Queue();q3=Queue();q4=Queue();q5=Queue();q6=Queue()
        if use_assetfinder:
            add_process(call_assetfinder,domain.name,q1)
        if use_subfinder:
            add_process(call_subfinder,domain.name,q2)
        if use_sublist3r:
            add_process(call_sublist3r,domain.name,q3)
        if use_findomain:
            add_process(call_findomain,domain.name,q4)
        if use_abuseip_api:
            add_process(call_abuse_ip,domain.name,q5)
        if use_certsh_api:
            add_process(call_certsh,domain.name,q6)
        for proc in processes:
            join_process(proc)
        
            
    except KeyboardInterrupt:
        pass
    finally:
        append_subdomains(q1)
        append_subdomains(q2)
        append_subdomains(q3)
        append_subdomains(q4)
        append_subdomains(q5)
        append_subdomains(q6)

            
    # db connection setup
    client = mongo.AsyncIOMotorClient(
        f'mongodb://{DB_USERNAME}:{DB_PASSWORD}@127.0.0.1/admin?retryWrites=true&w=majority')
    db = client[domain.name.replace('.','-')]
    

    # Get Resolver
    # https://github.com/BonJarber/fresh-resolvers
    os.system('rm -f resolvers.txt')
    os.system('wget https://github.com/BonJarber/fresh-resolvers/blob/main/resolvers.txt')


    merged_subdomains = list(set(subdomains))
    print("merged_subdomains",merged_subdomains)
    if return_diffrences:
        previous_inserted_subdomains=await db['subdomains'].find_one()
        returning_subdomains=merged_subdomains - previous_inserted_subdomains.names
    db['subdomains'].insert_one({'names':merged_subdomains})
    # if domain.generate_wordlist:
    #     # Bind Wordlist with domain --> <wordlist>.domain.tld
    #     # remove soon
    #     # os.chdir(path1)
    #     # os.system('cp wordlists/wordlist_1.txt DB-DNS-Brute/Bind_domain_wordlist.txt')
    #     # os.system("sed -e 's/$/." + domain.name + "/' -i DB-DNS-Brute/Bind_domain_wordlist.txt")
    #     # print('[+] Generate Wordlist.' + domain.name + ' Ok\n')

    #     os.system('mkdir ./' + domain.name)
    #     os.system('cp wordlists/wordlist_1.txt ./' + domain.name + '/bind_domain.txt')
    #     generated_subdomains = subprocess.Popen(
    #         "sed -e 's/$/." + domain.name + "/' -i ./" + domain.name + '/bind_domain.txt', stdout=subprocess.PIPE,
    #         stderr=subprocess.PIPE)
    #     out, err = generated_subdomains.communicate()
    #     async with aiofiles.open('filename', mode='r') as f:
    #         async for line in f:
    #             print(line)

    #     # Merge Wordlist.domain.tld with Provider
    #     os.system(
    #         'cat DB-DNS-Brute/no_duplicate.txt DB-DNS-Brute/Bind_domain_wordlist.txt | sort -u >> DB-DNS-Brute/Merge_subdomains_2.txt')

    #     # shuffledns-step1
    #     os.system(
    #         'shuffledns -d ' + domain.name + ' -list DB-DNS-Brute/Merge_subdomains_2.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_1.txt')

    #     # DNSGen
    #     os.system(
    #         'cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/no_duplicate.txt | sort -u | dnsgen - >> DB-DNS-Brute/dnsgen.txt')

    #     # shuffledns-step2
    #     os.system(
    #         'shuffledns -d ' + domain.name + ' -list DB-DNS-Brute/dnsgen.txt -r resolvers.txt -silent > DB-DNS-Brute/Resolve_2.txt')

    #     # Merge_Resolved
    #     os.system(
    #         'cat DB-DNS-Brute/Resolve_1.txt DB-DNS-Brute/Resolve_2.txt | sort -u >> DB-DNS-Resolve/' + domain_path + '/' + domain_path + '.txt')

    # Send END Notify
    # os.system("echo  'DNS-Brute(" + domain +  ") -->  END' | notify -id '***'")


# Python 3.7+
asyncio.run(main())

