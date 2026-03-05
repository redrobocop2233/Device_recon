import socket
import dns.resolver
import whois
import ssl
import requests
from datetime import datetime
import json
import pyfiglet
from colorama import init, Fore, Style
import concurrent.futures
import matplotlib.pyplot as plt
import networkx as nx
import re

init(autoreset=True)

class DomainReconTool:
    def __init__(self, domain):
        # Clean the domain input (remove http://, https://, www., trailing slashes)
        self.raw_input = domain
        self.domain = self.clean_domain(domain)
        self.results = {
            'domain': self.domain,
            'original_input': domain,
            'ip': None,
            'dns_records': {},
            'whois': {},
            'ssl': {},
            'subdomains': [],
            'open_ports': []
        }
    
    def clean_domain(self, domain):
        """Remove http://, https://, www., trailing slashes from domain"""
        # Remove http:// or https://
        domain = re.sub(r'^https?://', '', domain)
        # Remove www.
        domain = re.sub(r'^www\.', '', domain)
        # Remove trailing slash and everything after
        domain = domain.split('/')[0]
        # Remove anything after : (port)
        domain = domain.split(':')[0]
        return domain.lower()
    
    def safe_filename(self, text):
        """Convert text to safe filename"""
        # Replace invalid characters with underscore
        return re.sub(r'[^\w\-_\. ]', '_', text)
    
    def print_banner(self):
        banner = pyfiglet.figlet_format("DOMAIN RECON")
        print(Fore.CYAN + banner)
        print(Fore.YELLOW + "=" * 60)
        print(Fore.GREEN + f"Target: {self.raw_input}")
        print(Fore.GREEN + f"Cleaned Domain: {self.domain}")
        print(Fore.YELLOW + "=" * 60 + "\n")
    
    def get_ip(self):
        try:
            self.results['ip'] = socket.gethostbyname(self.domain)
            print(Fore.GREEN + f"[+] IP Address: {self.results['ip']}")
        except socket.gaierror:
            print(Fore.RED + f"[-] Could not resolve IP for {self.domain}")
        except Exception as e:
            print(Fore.RED + f"[-] Error: {e}")
    
    def get_dns_records(self):
        print(Fore.CYAN + "\n[+] DNS Records")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record)
                self.results['dns_records'][record] = [str(rdata) for rdata in answers]
                for rdata in answers:
                    print(Fore.WHITE + f"  {record}: {rdata}")
            except dns.resolver.NoAnswer:
                self.results['dns_records'][record] = []
            except dns.resolver.NXDOMAIN:
                print(Fore.RED + f"  {record}: Domain does not exist")
                break
            except Exception as e:
                self.results['dns_records'][record] = []
    
    def get_whois_info(self):
        print(Fore.CYAN + "\n[+] WHOIS Information")
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'name_servers': [str(ns) for ns in (w.name_servers or [])]
            }
            print(Fore.WHITE + f"  Registrar: {w.registrar or 'N/A'}")
            print(Fore.WHITE + f"  Creation: {w.creation_date or 'N/A'}")
            print(Fore.WHITE + f"  Expires: {w.expiration_date or 'N/A'}")
        except Exception as e:
            print(Fore.RED + f"  [-] WHOIS lookup failed: {e}")
    
    def get_ssl_info(self):
        print(Fore.CYAN + "\n[+] SSL Certificate")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl'] = {
                        'issuer': str(cert.get('issuer', 'N/A')),
                        'notAfter': cert.get('notAfter', 'N/A'),
                        'subject': str(cert.get('subject', 'N/A'))
                    }
                    print(Fore.WHITE + f"  Issuer: {cert.get('issuer', 'N/A')}")
                    print(Fore.WHITE + f"  Valid Until: {cert.get('notAfter', 'N/A')}")
        except Exception as e:
            print(Fore.RED + f"  [-] SSL not available: {e}")
    
    def scan_ports(self):
        if not self.results['ip']:
            print(Fore.RED + "\n[-] Cannot scan ports without IP address")
            return
            
        print(Fore.CYAN + "\n[+] Port Scanning")
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443]
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.results['ip'], port))
                sock.close()
                if result == 0:
                    service = self.get_service_name(port)
                    self.results['open_ports'].append({'port': port, 'service': service})
                    print(Fore.GREEN + f"  Port {port}: OPEN ({service})")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_port, common_ports)
    
    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")
    
    def discover_subdomains(self):
        print(Fore.CYAN + "\n[+] Subdomain Discovery")
        subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 
                     'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 
                     'autodiscover', 'autoconfig', 'm', 'imap', 'test', 
                     'ns', 'blog', 'dev', 'api', 'secure', 'vpn', 'admin',
                     'support', 'help', 'mail2', 'email', 'web', 'server',
                     'remote', 'portal', 'login', 'account', 'pay', 'payment']
        
        found = []
        for sub in subdomains:
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append(subdomain)
                print(Fore.GREEN + f"  [+] {subdomain} -> {ip}")
            except socket.gaierror:
                pass
            except Exception as e:
                pass
        
        self.results['subdomains'] = found
        if not found:
            print(Fore.YELLOW + "  No subdomains found")
    
    def visualize_infrastructure(self):
        if not self.results['ip'] and not self.results['subdomains'] and not self.results['dns_records'].get('NS'):
            print(Fore.YELLOW + "\n[-] Not enough data to generate visualization")
            return
            
        print(Fore.CYAN + "\n[+] Generating Infrastructure Graph...")
        
        try:
            G = nx.Graph()
            G.add_node(self.domain, color='red', size=3000)
            
            # Add IP node
            if self.results['ip']:
                G.add_node(self.results['ip'], color='blue', size=2000)
                G.add_edge(self.domain, self.results['ip'])
            
            # Add subdomains (limit to 10 for readability)
            for sub in self.results['subdomains'][:10]:
                G.add_node(sub, color='green', size=1500)
                G.add_edge(self.domain, sub)
            
            # Add DNS servers
            if 'NS' in self.results['dns_records']:
                for ns in self.results['dns_records']['NS'][:5]:
                    G.add_node(ns, color='orange', size=1000)
                    G.add_edge(self.domain, ns)
            
            # Add mail servers
            if 'MX' in self.results['dns_records']:
                for mx in self.results['dns_records']['MX'][:3]:
                    # Extract hostname from MX record (format: "10 mail.example.com")
                    mx_host = mx.split()[-1] if ' ' in mx else mx
                    G.add_node(mx_host, color='purple', size=1200)
                    G.add_edge(self.domain, mx_host)
            
            plt.figure(figsize=(14, 10))
            pos = nx.spring_layout(G, k=2, iterations=50)
            
            # Draw nodes with different colors
            colors = [G.nodes[node].get('color', 'gray') for node in G.nodes()]
            sizes = [G.nodes[node].get('size', 1000) for node in G.nodes()]
            
            nx.draw(G, pos, node_color=colors, node_size=sizes, 
                    with_labels=True, font_size=8, font_weight='bold', 
                    font_family='sans-serif', edge_color='gray', width=0.5)
            
            plt.title(f"Infrastructure Map for {self.domain}", fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            # Create safe filename
            safe_domain = self.safe_filename(self.domain)
            filename = f"reports/{safe_domain}_graph.png"
            
            # Ensure reports directory exists
            import os
            os.makedirs('reports', exist_ok=True)
            
            plt.savefig(filename, dpi=300, bbox_inches='tight', format='png')
            plt.close()
            print(Fore.GREEN + f"  [✓] Graph saved to {filename}")
            
        except Exception as e:
            print(Fore.RED + f"  [-] Graph generation failed: {e}")
    
    def save_report(self):
        # Ensure reports directory exists
        import os
        os.makedirs('reports', exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = self.safe_filename(self.domain)
        filename = f"reports/{safe_domain}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, default=str, ensure_ascii=False)
            print(Fore.GREEN + f"\n[✓] Report saved to {filename}")
        except Exception as e:
            print(Fore.RED + f"\n[-] Failed to save report: {e}")
    
    def run(self):
        try:
            self.print_banner()
            self.get_ip()
            self.get_dns_records()
            self.get_whois_info()
            self.get_ssl_info()
            self.scan_ports()
            self.discover_subdomains()
            self.visualize_infrastructure()
            self.save_report()
            print(Fore.CYAN + "\n" + "=" * 60)
            print(Fore.GREEN + "✅ Reconnaissance completed successfully!")
            print(Fore.CYAN + "=" * 60)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n⚠️  Interrupted by user")
        except Exception as e:
            print(Fore.RED + f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain or URL: ")
    
    tool = DomainReconTool(domain)
    tool.run()