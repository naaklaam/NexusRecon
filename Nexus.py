#!/usr/bin/env python3
# NexusRecon - Advanced OSINT Reconnaissance Tool
# Lebih canggih dari theHarvester dengan fitur tambahan

import requests
import json
import threading
import time
import argparse
import re
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures
from itertools import cycle
import random

class NexusRecon:
    def __init__(self):
        self.results = {
            'emails': set(),
            'subdomains': set(),
            'hosts': set(),
            'urls': set(),
            'social_media': set(),
            'employees': set(),
            'technologies': set(),
            'dns_records': {},
            'whois_info': {}
        }
        
        # User agents untuk menghindari blocking
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        self.current_user_agent = cycle(self.user_agents)
        
        # API keys (bisa diisi jika punya)
        self.securitytrails_api = ""
        self.shodan_api = ""
        self.virustotal_api = ""
        
    def get_random_headers(self):
        return {
            'User-Agent': next(self.current_user_agent),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    def search_google(self, query, num_results=50):
        """Search using Google dorks"""
        results = []
        try:
            headers = self.get_random_headers()
            search_url = f"https://www.google.com/search?q={query}&num={num_results}"
            response = requests.get(search_url, headers=headers, timeout=10)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a')
            
            for link in links:
                href = link.get('href')
                if href and href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    results.append(url)
                    
        except Exception as e:
            print(f"[-] Google search error: {e}")
        
        return results
    
    def search_bing(self, query, num_results=50):
        """Search using Bing"""
        results = []
        try:
            headers = self.get_random_headers()
            search_url = f"https://www.bing.com/search?q={query}&count={num_results}"
            response = requests.get(search_url, headers=headers, timeout=10)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('li', class_='b_algo')
            
            for link in links:
                a_tag = link.find('a')
                if a_tag and a_tag.get('href'):
                    results.append(a_tag.get('href'))
                    
        except Exception as e:
            print(f"[-] Bing search error: {e}")
        
        return results
    
    def extract_emails(self, text):
        """Extract emails from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        for email in emails:
            if not email.endswith(('.png', '.jpg', '.gif', '.jpeg')):
                self.results['emails'].add(email)
    
    def extract_subdomains(self, domain):
        """Extract subdomains using various methods"""
        subdomains = set()
        
        # Method 1: Certificate transparency logs
        try:
            crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(crt_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and not name.startswith('*.'):
                        subdomains.add(name)
        except:
            pass
        
        # Method 2: DNS brute force (basic)
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'localhost', 'webmail', 'smtp',
            'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
            'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev',
            'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1',
            'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
            'wap', 'my', 'svn', 'shop', 'ftp2', 'blog', 'bbs', 'owa', 'forum',
            'owa', 'mail1', 'exchange', 'host', 'crm', 'cms', 'backup', 'mx2',
            'cloud', 'apps', 'stg', 'git', 'cdn2', 'db', 'stage', 'jenkins'
        ]
        
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except:
                pass
        
        self.results['subdomains'].update(subdomains)
        return subdomains
    
    def dns_enumeration(self, domain):
        """Comprehensive DNS enumeration"""
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'AAAA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                self.results['dns_records'][record_type] = []
                for answer in answers:
                    self.results['dns_records'][record_type].append(str(answer))
            except:
                pass
    
    def whois_lookup(self, domain):
        """WHOIS lookup"""
        try:
            w = whois.whois(domain)
            self.results['whois_info'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'registrant': w.org
            }
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")
    
    def social_media_harvest(self, company_name):
        """Harvest social media presence"""
        social_platforms = {
            'linkedin': f'site:linkedin.com "{company_name}"',
            'twitter': f'site:twitter.com "{company_name}"',
            'facebook': f'site:facebook.com "{company_name}"',
            'github': f'site:github.com "{company_name}"'
        }
        
        for platform, query in social_platforms.items():
            try:
                # Search using Google
                results = self.search_google(query, 20)
                for result in results:
                    if company_name.lower() in result.lower():
                        self.results['social_media'].add(result)
            except:
                pass
    
    def employee_harvest(self, company_name):
        """Harvest employee information"""
        employee_queries = [
            f'site:linkedin.com/in "{company_name}"',
            f'site:linkedin.com "{company_name}" "at {company_name}"',
        ]
        
        for query in employee_queries:
            try:
                results = self.search_google(query, 30)
                for result in results:
                    # Extract potential employee names
                    if '/in/' in query and 'linkedin.com' in query:
                        # Parse LinkedIn profiles
                        path_parts = urlparse(query).path.split('/')
                        if len(path_parts) > 2:
                            name = path_parts[2].replace('-', ' ').title()
                            self.results['employees'].add(name)
            except:
                pass
    
    def technology_detection(self, domain):
        """Detect technologies used by the target"""
        try:
            url = f"http://{domain}"
            response = requests.get(url, headers=self.get_random_headers(), timeout=10)
            
            # Check for common technologies in headers
            server = response.headers.get('Server', '')
            if server:
                self.results['technologies'].add(f"Server: {server}")
            
            # Check for common frameworks/CMS
            content = response.text.lower()
            tech_indicators = {
                'WordPress': ['wp-content', 'wordpress'],
                'Joomla': ['joomla', '/templates/'],
                'Drupal': ['drupal', '/sites/all/'],
                'Shopify': ['shopify', 'myshopify'],
                'Magento': ['magento', '/skin/frontend/']
            }
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        self.results['technologies'].add(tech)
                        break
                        
        except:
            pass
    
    def advanced_search(self, domain, company_name):
        """Advanced search with multiple techniques"""
        
        # Email harvesting
        email_queries = [
            f"site:{domain} intext:@{domain}",
            f"site:{domain} \"@{domain}\"",
            f"site:{domain} filetype:pdf \"@{domain}\"",
            f"site:{domain} filetype:doc \"@{domain}\""
        ]
        
        for query in email_queries:
            try:
                results = self.search_google(query, 20)
                for result in results:
                    # Fetch and parse content
                    try:
                        content_response = requests.get(result, headers=self.get_random_headers(), timeout=5)
                        self.extract_emails(content_response.text)
                    except:
                        pass
            except:
                pass
        
        # URL harvesting
        url_queries = [
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} inurl:wp-admin",
            f"site:{domain} inurl:dashboard"
        ]
        
        for query in url_queries:
            try:
                results = self.search_google(query, 20)
                for result in results:
                    self.results['urls'].add(result)
            except:
                pass
    
    def run_securitytrails(self, domain):
        """Use SecurityTrails API if available"""
        if not self.securitytrails_api:
            return
            
        try:
            headers = {
                'APIKEY': self.securitytrails_api,
                'accept': 'application/json'
            }
            
            # Get subdomains
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                for sub in subdomains:
                    self.results['subdomains'].add(f"{sub}.{domain}")
                    
        except Exception as e:
            print(f"[-] SecurityTrails API error: {e}")
    
    def comprehensive_recon(self, domain, company_name=None):
        """Run comprehensive reconnaissance"""
        print(f"[+] Starting comprehensive reconnaissance for {domain}")
        
        if not company_name:
            company_name = domain.split('.')[0].title()
        
        # Create threads for different tasks
        threads = []
        
        # Basic enumeration
        threads.append(threading.Thread(target=self.extract_subdomains, args=(domain,)))
        threads.append(threading.Thread(target=self.dns_enumeration, args=(domain,)))
        threads.append(threading.Thread(target=self.whois_lookup, args=(domain,)))
        
        # Advanced harvesting
        threads.append(threading.Thread(target=self.social_media_harvest, args=(company_name,)))
        threads.append(threading.Thread(target=self.employee_harvest, args=(company_name,)))
        threads.append(threading.Thread(target=self.technology_detection, args=(domain,)))
        threads.append(threading.Thread(target=self.advanced_search, args=(domain, company_name,)))
        
        # External API calls
        threads.append(threading.Thread(target=self.run_securitytrails, args=(domain,)))
        
        # Start all threads
        for thread in threads:
            thread.start()
            time.sleep(0.5)  # Small delay to avoid overwhelming
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        print("[+] Reconnaissance completed!")
    
    def save_results(self, filename):
        """Save results to file"""
        with open(filename, 'w') as f:
            f.write("# NexusRecon Results\n")
            f.write(f"# Generated at {time.ctime()}\n\n")
            
            f.write("## EMAILS\n")
            for email in sorted(self.results['emails']):
                f.write(f"{email}\n")
            
            f.write("\n## SUBDOMAINS\n")
            for subdomain in sorted(self.results['subdomains']):
                f.write(f"{subdomain}\n")
            
            f.write("\n## HOSTS\n")
            for host in sorted(self.results['hosts']):
                f.write(f"{host}\n")
            
            f.write("\n## URLs\n")
            for url in sorted(self.results['urls']):
                f.write(f"{url}\n")
            
            f.write("\n## SOCIAL MEDIA\n")
            for sm in sorted(self.results['social_media']):
                f.write(f"{sm}\n")
            
            f.write("\n## EMPLOYEES\n")
            for employee in sorted(self.results['employees']):
                f.write(f"{employee}\n")
            
            f.write("\n## TECHNOLOGIES\n")
            for tech in sorted(self.results['technologies']):
                f.write(f"{tech}\n")
            
            f.write("\n## DNS RECORDS\n")
            for record_type, records in self.results['dns_records'].items():
                f.write(f"{record_type}: {', '.join(records)}\n")
            
            f.write("\n## WHOIS INFO\n")
            for key, value in self.results['whois_info'].items():
                f.write(f"{key}: {value}\n")
        
        print(f"[+] Results saved to {filename}")
    
    def print_results(self):
        """Print results to console"""
        print("\n" + "="*50)
        print("NEXUSRECON RESULTS")
        print("="*50)
        
        if self.results['emails']:
            print(f"\n📧 EMAILS ({len(self.results['emails'])}):")
            for email in sorted(self.results['emails'])[:20]:  # Show top 20
                print(f"  {email}")
            if len(self.results['emails']) > 20:
                print(f"  ... and {len(self.results['emails']) - 20} more")
        
        if self.results['subdomains']:
            print(f"\n🌐 SUBDOMAINS ({len(self.results['subdomains'])}):")
            for subdomain in sorted(self.results['subdomains'])[:20]:
                print(f"  {subdomain}")
            if len(self.results['subdomains']) > 20:
                print(f"  ... and {len(self.results['subdomains']) - 20} more")
        
        if self.results['social_media']:
            print(f"\n📱 SOCIAL MEDIA ({len(self.results['social_media'])}):")
            for sm in sorted(self.results['social_media']):
                print(f"  {sm}")
        
        if self.results['employees']:
            print(f"\n👥 EMPLOYEES ({len(self.results['employees'])}):")
            for employee in sorted(self.results['employees']):
                print(f"  {employee}")
        
        if self.results['technologies']:
            print(f"\n🛠 TECHNOLOGIES ({len(self.results['technologies'])}):")
            for tech in sorted(self.results['technologies']):
                print(f"  {tech}")
        
        if self.results['urls']:
            print(f"\n🔗 POTENTIAL TARGETS ({len(self.results['urls'])}):")
            for url in sorted(self.results['urls'])[:10]:
                print(f"  {url}")
            if len(self.results['urls']) > 10:
                print(f"  ... and {len(self.results['urls']) - 10} more")

def main():
    parser = argparse.ArgumentParser(description='NexusRecon - Advanced OSINT Tool')
    parser.add_argument('-d', '--domain', help='Target domain', required=True)
    parser.add_argument('-n', '--name', help='Company name')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--securitytrails', help='SecurityTrails API key')
    parser.add_argument('--shodan', help='Shodan API key')
    
    args = parser.parse_args()
    
    # Initialize recon tool
    recon = NexusRecon()
    
    # Set API keys if provided
    if args.securitytrails:
        recon.securitytrails_api = args.securitytrails
    if args.shodan:
        recon.shodan_api = args.shodan
    
    # Start reconnaissance
    start_time = time.time()
    recon.comprehensive_recon(args.domain, args.name)
    end_time = time.time()
    
    # Display results
    recon.print_results()
    
    # Save results if output file specified
    if args.output:
        recon.save_results(args.output)
    
    print(f"\n⏱ Reconnaissance completed in {end_time - start_time:.2f} seconds")
    print("🎯 Happy hunting!")

if __name__ == "__main__":
    try:
        import dns.resolver
        import whois
        main()
    except ImportError as e:
        print("❌ Missing dependencies. Install with:")
        print("pip install requests beautifulsoup4 dnspython python-whois")
