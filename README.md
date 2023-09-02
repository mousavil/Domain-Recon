# Domain Reconnaissance Suite

The ultimate subdomain and domain reconnaissance toolkit for pentesters and bug bounty hunters.

Domain Reconnaissance Suite automates the process of thoroughly mapping an organization's external digital footprint and attack surface using both active and passive discovery techniques.

![Screenshot from 2023-09-02 14-48-52](https://github.com/mousavil/Domain-Recon/assets/54477292/0031b922-7201-4417-9485-24a43f88e8dd)

## Features

- **Subdomain Enumeration** - Uses multiple subdomain discovery techniques:

  - Certificate transparency 

  - Reverse DNS

  - Brute forcing

  - Scraping (CRT.sh, CertSpotter) 

  - Permutations/DNS buffer overflows

- **Permutation Generation** - Automatically generate subdomain permutations and variations using DNSGen to maximize discoveries

- **Domain Validation** - Filter out invalid domains using shuffledns to verify resolved IPs 

- **Reconnaissance** - Perform preliminary analysis on discovered assets:
  - Probe for live hosts 
  - Screenshot web services
  - Discover content and technologies
  - Fingerprint CMS and frameworks
  - Check for takeovers and exposures

- **Data Analysis** - All results are automatically consolidated in a local database for easy analysis and diffing against previous recon efforts

- **Latest Tools** - Leverage the latest and greatest subdomain enumeration tools like Subfinder, crt.sh, Certspotter, and Amass

- **Extensively Configurable** - Tune every aspect of the workflow via the config file

## Usage

```
domain-recon -d example.com

Optional arguments:
-d --domain    Target domain 
-c --config    Configuration file  
-o --output    Output directory
```

## Why Domain Reconnaissance Suite?

Manually gathering and analyzing domain and subdomain intelligence can take hours. Domain Recon Suite automates the entire workflow allowing you to go from zero to recon in minutes.

It uses an optimal combination of the latest OSINT tools and techniques to maximize coverage of an organization's external footprint. The automated nature eliminates tedious manual analysis and formatting.

The consolidated database combined with diffing makes it easy to track assets over time during ongoing engagements.

## How it Works

The workflow consists of:

1. Subdomain discovery via various passive and active techniques.

2. Compiling all raw subdomains and generating permutations.

3. Validation via DNS resolution to filter invalid domains.

4. Preliminary reconnaissance on each subdomain.

5. Consolidated domain intelligence saved to the local database.


## Contributing

Domain Recon Suite is built on open source and contributions are welcome! 

Some ideas:
- Add new domain discovery sources 
- Expand reconnaissance checks
- Improve reporting
- Integrate with other security tools


# Requirements

> install massdns

https://github.com/blechschmidt/massdns

> install shuffledns

https://github.com/projectdiscovery/shuffledns

> install dnsgen

https://github.com/ProjectAnte/dnsgen

> install subfinder

https://github.com/projectdiscovery/subfinder

> install Sublist3r

https://github.com/aboul3la/Sublist3r

> install find domain

https://github.com/Findomain/Findomain

> install assetfinder

https://github.com/tomnomnom/assetfinder

> install deduplicate

https://github.com/nytr0gen/deduplicate

# Set Path in Script

path1 = "/root/**script path***/dns_brute"

path2 = "/root/**script path***/dns_brute/DB-DNS-Brute"
