#!/usr/bin/env python3
"""
NetSec Toolkit - Comprehensive Network Security Suite
Integrates Packet Analysis, Vulnerability Scanning, and Security Testing

Coded By: Infinity_sec (Nir_____)
Version: 2.0

WARNING: Only use on systems you own or have explicit written permission to test.
Unauthorized use is illegal and may violate laws including CFAA.
"""

import socket
import struct
import sys
import argparse
import ssl
import json
import re
import datetime
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

warnings.filterwarnings('ignore')

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Display main banner"""
    banner = f"""{Colors.RED}
 _   _      _   ____            _____           _ _    _ _   
| \ | | ___| |_/ ___|  ___  ___|_   _|__   ___ | | | _(_) |_ 
|  \| |/ _ \ __\___ \ / _ \/ __| | |/ _ \ / _ \| | |/ / | __|
| |\  |  __/ |_ ___) |  __/ (__  | | (_) | (_) | |   <| | |_ 
|_| \_|\___|\__|____/ \___|\___| |_|\___/ \___/|_|_|\_\_|\__|
{Colors.END}
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║          Comprehensive Network Security Suite v2.0                        ║
║                  Coded By: Infinity_sec (Nir_____)                        ║
║                                                                           ║
║  Features: Packet Analysis • Vulnerability Scanning • OWASP Testing      ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_action_banner(action_name):
    """Print banner during actions"""
    width = 70
    print(f"\n{Colors.CYAN}{'='*width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.WHITE}{action_name.center(width)}{Colors.END}")
    print(f"{Colors.CYAN}{'='*width}{Colors.END}\n")

# ============================================================================
# PACKET CAPTURE MODULE
# ============================================================================

class PacketCapture:
    """Handles raw packet capture and analysis"""
    
    def __init__(self, interface='', max_packets=None):
        self.interface = interface
        self.packet_count = 0
        self.packets = []
        self.max_packets = max_packets
        self.sock = None
        
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            if sys.platform == 'win32':
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.get_local_ip(), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print(f"{Colors.GREEN}[+] Packet capture socket created successfully{Colors.END}")
            return True
        except PermissionError:
            print(f"{Colors.RED}[!] Permission denied. Run with administrator/sudo privileges{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Error creating socket: {e}{Colors.END}")
            return False
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def capture_packets(self):
        """Capture packets until user stops or limit reached"""
        print(f"{Colors.CYAN}[*] Starting packet capture...{Colors.END}")
        if self.max_packets:
            print(f"{Colors.CYAN}[*] Will capture {self.max_packets} packets{Colors.END}")
        else:
            print(f"{Colors.CYAN}[*] Press Ctrl+C to stop capture{Colors.END}\n")
        
        try:
            while True:
                if self.max_packets and self.packet_count >= self.max_packets:
                    break
                    
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1
                
                timestamp = datetime.datetime.now()
                packet_info = self.parse_packet(raw_data, timestamp)
                
                if packet_info:
                    self.packets.append(packet_info)
                    self.display_packet_summary(packet_info, self.packet_count)
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Capture stopped by user{Colors.END}")
        finally:
            if sys.platform == 'win32' and self.sock:
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            if self.sock:
                self.sock.close()
            print(f"\n{Colors.GREEN}[+] Captured {self.packet_count} packets total{Colors.END}")
    
    def parse_packet(self, raw_data, timestamp):
        """Parse raw packet data"""
        packet = {'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}
        
        try:
            if sys.platform != 'win32' and len(raw_data) > 14:
                eth_header = raw_data[:14]
                packet['eth'] = self.parse_ethernet(eth_header)
                raw_data = raw_data[14:]
            
            if len(raw_data) >= 20:
                ip_header = raw_data[:20]
                packet['ip'] = self.parse_ipv4(ip_header)
                
                protocol = packet['ip']['protocol']
                data = raw_data[packet['ip']['header_length']:]
                
                if protocol == 6 and len(data) >= 20:
                    packet['tcp'] = self.parse_tcp(data)
                    packet['protocol_name'] = 'TCP'
                elif protocol == 17 and len(data) >= 8:
                    packet['udp'] = self.parse_udp(data)
                    packet['protocol_name'] = 'UDP'
                elif protocol == 1 and len(data) >= 8:
                    packet['icmp'] = self.parse_icmp(data)
                    packet['protocol_name'] = 'ICMP'
                else:
                    packet['protocol_name'] = f'Protocol-{protocol}'
                
                return packet
        except Exception as e:
            pass
        
        return None
    
    def parse_ethernet(self, data):
        """Parse Ethernet header"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data)
        return {
            'dest_mac': self.format_mac(dest_mac),
            'src_mac': self.format_mac(src_mac),
            'protocol': proto
        }
    
    def parse_ipv4(self, data):
        """Parse IPv4 header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': proto,
            'src': self.ipv4(src),
            'dest': self.ipv4(dest)
        }
    
    def parse_tcp(self, data):
        """Parse TCP segment"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': (offset_reserved_flags & 32) >> 5,
                'ACK': (offset_reserved_flags & 16) >> 4,
                'PSH': (offset_reserved_flags & 8) >> 3,
                'RST': (offset_reserved_flags & 4) >> 2,
                'SYN': (offset_reserved_flags & 2) >> 1,
                'FIN': offset_reserved_flags & 1
            }
        }
    
    def parse_udp(self, data):
        """Parse UDP segment"""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return {'src_port': src_port, 'dest_port': dest_port, 'size': size}
    
    def parse_icmp(self, data):
        """Parse ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return {'type': icmp_type, 'code': code, 'checksum': checksum}
    
    @staticmethod
    def ipv4(addr):
        return '.'.join(map(str, addr))
    
    @staticmethod
    def format_mac(addr):
        return ':'.join(map('{:02x}'.format, addr))
    
    def display_packet_summary(self, packet, num):
        """Display one-line packet summary"""
        proto = packet.get('protocol_name', 'Unknown')
        src = packet['ip']['src']
        dest = packet['ip']['dest']
        
        info = f"{src} → {dest}"
        
        if 'tcp' in packet:
            info += f" [TCP {packet['tcp']['src_port']}→{packet['tcp']['dest_port']}]"
        elif 'udp' in packet:
            info += f" [UDP {packet['udp']['src_port']}→{packet['udp']['dest_port']}]"
        
        print(f"[{num:04d}] {packet['timestamp']} | {proto:8s} | {info}")

class PacketAnalyzer:
    """Analyzes captured packets for statistics and patterns"""
    
    def __init__(self, packets):
        self.packets = packets
    
    def generate_statistics(self):
        """Generate packet statistics"""
        stats = {
            'total_packets': len(self.packets),
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'port_distribution': defaultdict(int)
        }
        
        for packet in self.packets:
            proto = packet.get('protocol_name', 'Unknown')
            stats['protocols'][proto] += 1
            
            if 'ip' in packet:
                stats['top_sources'][packet['ip']['src']] += 1
                stats['top_destinations'][packet['ip']['dest']] += 1
            
            if 'tcp' in packet:
                for flag, value in packet['tcp']['flags'].items():
                    if value:
                        stats['tcp_flags'][flag] += 1
                stats['port_distribution'][packet['tcp']['dest_port']] += 1
            
            if 'udp' in packet:
                stats['port_distribution'][packet['udp']['dest_port']] += 1
        
        return stats
    
    def display_statistics(self, stats):
        """Display formatted statistics"""
        print_action_banner("PACKET ANALYSIS STATISTICS")
        
        print(f"{Colors.WHITE}Total Packets Captured: {Colors.GREEN}{stats['total_packets']}{Colors.END}\n")
        
        print(f"{Colors.YELLOW}Protocol Distribution:{Colors.END}")
        print("-" * 40)
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets']) * 100
            print(f"  {proto:15s}: {count:4d} ({percentage:5.1f}%)")
        
        print(f"\n{Colors.YELLOW}Top 5 Source IPs:{Colors.END}")
        print("-" * 40)
        for ip, count in sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:15s}: {count:4d} packets")
        
        print(f"\n{Colors.YELLOW}Top 5 Destination IPs:{Colors.END}")
        print("-" * 40)
        for ip, count in sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:15s}: {count:4d} packets")
        
        if stats['tcp_flags']:
            print(f"\n{Colors.YELLOW}TCP Flags Distribution:{Colors.END}")
            print("-" * 40)
            for flag, count in sorted(stats['tcp_flags'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {flag:5s}: {count:4d}")
    
    def detect_suspicious_activity(self):
        """Detect potentially suspicious network patterns"""
        alerts = []
        
        # Port scanning detection
        source_ports = defaultdict(set)
        for packet in self.packets:
            if 'tcp' in packet and 'ip' in packet:
                src = packet['ip']['src']
                dest_port = packet['tcp']['dest_port']
                source_ports[src].add(dest_port)
        
        for src, ports in source_ports.items():
            if len(ports) > 10:
                alerts.append({
                    'type': 'Possible Port Scan',
                    'severity': 'HIGH',
                    'source': src,
                    'details': f'Accessed {len(ports)} different ports'
                })
        
        # SYN flood detection
        syn_counts = defaultdict(int)
        for packet in self.packets:
            if 'tcp' in packet and packet['tcp']['flags']['SYN'] and not packet['tcp']['flags']['ACK']:
                syn_counts[packet['ip']['src']] += 1
        
        for src, count in syn_counts.items():
            if count > 50:
                alerts.append({
                    'type': 'Possible SYN Flood',
                    'severity': 'CRITICAL',
                    'source': src,
                    'details': f'{count} SYN packets detected'
                })
        
        return alerts
    
    def display_alerts(self, alerts):
        """Display security alerts"""
        if alerts:
            print_action_banner("SECURITY ALERTS")
            
            for i, alert in enumerate(alerts, 1):
                severity_color = Colors.RED if alert['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"{severity_color}[Alert {i}] {alert['type']} - {alert['severity']}{Colors.END}")
                print(f"  Source: {alert['source']}")
                print(f"  Details: {alert['details']}\n")
        else:
            print(f"\n{Colors.GREEN}[+] No suspicious activity detected{Colors.END}")

# ============================================================================
# VULNERABILITY SCANNER MODULE
# ============================================================================

class VulnerabilityDatabase:
    """Database of known vulnerabilities"""
    
    VULNERABLE_VERSIONS = {
        'Apache': {
            '2.4.49': {'cve': 'CVE-2021-41773', 'severity': 'CRITICAL', 'description': 'Path Traversal and RCE'},
            '2.4.50': {'cve': 'CVE-2021-42013', 'severity': 'CRITICAL', 'description': 'Path Traversal and RCE'},
        },
        'nginx': {
            '1.3.9-1.4.0': {'cve': 'CVE-2013-2028', 'severity': 'HIGH', 'description': 'Memory Disclosure'},
        },
        'OpenSSH': {
            '7.4': {'cve': 'CVE-2018-15473', 'severity': 'MEDIUM', 'description': 'Username Enumeration'},
        },
        'MySQL': {
            '5.7.0-5.7.23': {'cve': 'CVE-2018-3081', 'severity': 'HIGH', 'description': 'Multiple Vulnerabilities'},
        }
    }
    
    OWASP_TOP_10 = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable and Outdated Components',
        'A07': 'Identification and Authentication Failures'
    }

class VulnerabilityScanner:
    """Comprehensive vulnerability scanner"""
    
    def __init__(self, target, ports=None, web_scan=True):
        self.target = target
        self.ports = ports or range(1, 1025)
        self.web_scan = web_scan
        self.results = {
            'target': target,
            'scan_time': str(datetime.datetime.now()),
            'ip_address': None,
            'open_ports': [],
            'services': {},
            'vulnerabilities': [],
            'ssl_issues': [],
            'risk_score': 0
        }
    
    def resolve_target(self):
        """Resolve hostname to IP"""
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip_address'] = ip
            print(f"{Colors.GREEN}[+] Target: {self.target} ({ip}){Colors.END}")
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}[-] Cannot resolve hostname: {self.target}{Colors.END}")
            sys.exit(1)
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def port_scan(self):
        """Multi-threaded port scanning"""
        print(f"\n{Colors.CYAN}[*] Scanning ports on {self.target}...{Colors.END}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    print(f"{Colors.GREEN}[+] Port {port} is OPEN{Colors.END}")
        
        self.results['open_ports'] = sorted(open_ports)
        return open_ports
    
    def grab_banner(self, port):
        """Banner grabbing with service-specific probes"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            if port in [80, 443, 8080, 8443]:
                request = f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                sock.send(request.encode())
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return None
    
    def detect_service(self, port):
        """Service detection with version extraction"""
        common_services = {
            21: 'FTP', 22: 'SSH', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 5900: 'VNC', 1433: 'MSSQL'
        }
        
        service_info = {
            'port': port,
            'service': common_services.get(port, 'Unknown'),
            'version': 'Unknown',
            'banner': None
        }
        
        banner = self.grab_banner(port)
        if banner:
            service_info['banner'] = banner[:300]
            
            version_patterns = [
                r'Apache[/\s]+([\d.]+)',
                r'nginx[/\s]+([\d.]+)',
                r'OpenSSH[_\s]+([\d.]+)',
                r'MySQL[/\s]+([\d.]+)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service_info['version'] = match.group(1)
                    service_name = re.search(r'([A-Za-z-]+)', pattern).group(1)
                    service_info['service'] = service_name
                    break
        
        return service_info
    
    def service_detection(self, open_ports):
        """Detect services on all open ports"""
        print(f"\n{Colors.CYAN}[*] Performing service detection...{Colors.END}")
        
        for port in open_ports:
            service_info = self.detect_service(port)
            self.results['services'][port] = service_info
            print(f"{Colors.GREEN}[+] Port {port}: {service_info['service']} {service_info['version']}{Colors.END}")
    
    def check_ssl_tls(self, port):
        """SSL/TLS security analysis"""
        print(f"\n{Colors.CYAN}[*] Analyzing SSL/TLS on port {port}...{Colors.END}")
        ssl_issues = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_issues.append({
                            'type': 'Weak Protocol',
                            'severity': 'HIGH',
                            'description': f'Outdated protocol {version} enabled'
                        })
                    
                    print(f"{Colors.GREEN}[+] SSL/TLS Version: {version}{Colors.END}")
                    if cipher:
                        print(f"{Colors.GREEN}[+] Cipher: {cipher[0]}{Colors.END}")
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] SSL/TLS check failed: {str(e)}{Colors.END}")
        
        self.results['ssl_issues'].extend(ssl_issues)
        return ssl_issues
    
    def check_web_vulnerabilities(self, port):
        """OWASP Top 10 web vulnerability checks"""
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.YELLOW}[!] Requests library not available - skipping web checks{Colors.END}")
            return
        
        print(f"\n{Colors.CYAN}[*] Checking web vulnerabilities on port {port}...{Colors.END}")
        
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{self.target}:{port}"
        
        try:
            response = requests.get(base_url, timeout=5, verify=False)
        except:
            print(f"{Colors.RED}[-] Web server not accessible on port {port}{Colors.END}")
            return
        
        self.test_security_headers(base_url)
        self.test_common_vulnerabilities(base_url)
    
    def test_security_headers(self, base_url):
        """Test for missing security headers"""
        try:
            response = requests.get(base_url, timeout=5, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP'
            }
            
            for header, desc in security_headers.items():
                if header not in headers:
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'description': f'{desc} missing',
                        'header': header
                    })
                    print(f"{Colors.YELLOW}[!] Missing header: {header}{Colors.END}")
        except:
            pass
    
    def test_common_vulnerabilities(self, base_url):
        """Test for common vulnerabilities"""
        sensitive_files = ['/.git/config', '/.env', '/phpinfo.php', '/server-status']
        
        for file_path in sensitive_files:
            try:
                response = requests.get(base_url + file_path, timeout=3, verify=False)
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'HIGH',
                        'url': base_url + file_path,
                        'description': f'Sensitive file exposed: {file_path}'
                    })
                    print(f"{Colors.YELLOW}[!] Sensitive file found: {file_path}{Colors.END}")
            except:
                pass
    
    def check_vulnerable_components(self):
        """Check for vulnerable components"""
        print(f"\n{Colors.CYAN}[*] Checking for vulnerable components...{Colors.END}")
        
        for port, service in self.results['services'].items():
            service_name = service['service']
            version = service['version']
            
            if version != 'Unknown':
                if service_name in VulnerabilityDatabase.VULNERABLE_VERSIONS:
                    vuln_versions = VulnerabilityDatabase.VULNERABLE_VERSIONS[service_name]
                    
                    for vuln_ver, vuln_info in vuln_versions.items():
                        if version in vuln_ver or version == vuln_ver:
                            self.results['vulnerabilities'].append({
                                'type': 'Vulnerable Component',
                                'severity': vuln_info['severity'],
                                'service': service_name,
                                'version': version,
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description']
                            })
                            color = Colors.RED if vuln_info['severity'] == 'CRITICAL' else Colors.YELLOW
                            print(f"{color}[!] {vuln_info['severity']}: {service_name} {version} - {vuln_info['cve']}{Colors.END}")
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
        
        total_score = sum(severity_scores.get(v['severity'], 0) for v in self.results['vulnerabilities'])
        total_score += sum(severity_scores.get(s['severity'], 0) for s in self.results['ssl_issues'])
        
        self.results['risk_score'] = min(total_score, 100)
        
        if total_score >= 30:
            risk_level = "CRITICAL"
        elif total_score >= 20:
            risk_level = "HIGH"
        elif total_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return total_score, risk_level
    
    def generate_report(self):
        """Generate security report"""
        risk_score, risk_level = self.calculate_risk_score()
        
        risk_colors = {'CRITICAL': Colors.RED, 'HIGH': Colors.YELLOW, 'MEDIUM': Colors.BLUE, 'LOW': Colors.GREEN}
        risk_color = risk_colors.get(risk_level, Colors.WHITE)
        
        print_action_banner("VULNERABILITY SCAN REPORT")
        
        print(f"{Colors.WHITE}Target: {self.results['target']} ({self.results['ip_address']}){Colors.END}")
        print(f"{Colors.WHITE}Scan Date: {self.results['scan_time']}{Colors.END}")
        print(f"{Colors.WHITE}Risk Score: {risk_color}{risk_score}/100{Colors.END}")
        print(f"{Colors.WHITE}Risk Level: {risk_color}{risk_level}{Colors.END}")
        print(f"{Colors.WHITE}Open Ports: {Colors.GREEN}{len(self.results['open_ports'])}{Colors.END}")
        print(f"{Colors.WHITE}Vulnerabilities: {Colors.RED}{len(self.results['vulnerabilities'])}{Colors.END}\n")
        
        if self.results['vulnerabilities']:
            print(f"{Colors.BOLD}{Colors.RED}VULNERABILITY SUMMARY{Colors.END}")
            severity_count = defaultdict(int)
            for vuln in self.results['vulnerabilities']:
                severity_count[vuln['severity']] += 1
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity_count[severity] > 0:
                    color = risk_colors.get(severity, Colors.WHITE)
                    print(f"{color}  • {severity}: {severity_count[severity]}{Colors.END}")
    
    def run_full_scan(self):
        """Execute full vulnerability scan"""
        print_action_banner("VULNERABILITY SCANNING IN PROGRESS")
        
        self.resolve_target()
        open_ports = self.port_scan()
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.END}")
            return
        
        self.service_detection(open_ports)
        self.check_vulnerable_components()
        
        if self.web_scan:
            web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
            for port in web_ports:
                self.check_web_vulnerabilities(port)
        
        ssl_ports = [p for p in open_ports if p in [443, 8443]]
        for port in ssl_ports:
            self.check_ssl_tls(port)
        
        self.generate_report()

# ============================================================================
# REPORT EXPORTER
# ============================================================================

class ReportExporter:
    """Export analysis results to various formats"""
    
    @staticmethod
    def export_packet_analysis(packets, stats, alerts, filename='packet_analysis.md'):
        """Export packet analysis to Markdown"""
        with open(filename, 'w') as f:
            f.write("# Network Packet Analysis Report\n\n")
            f.write(f"**Report Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Packets Captured:** {stats['total_packets']}\n")
            if packets:
                f.write(f"- **Capture Start:** {packets[0]['timestamp']}\n")
                f.write(f"- **Capture End:** {packets[-1]['timestamp']}\n")
            f.write("\n")
            
            f.write("## Protocol Distribution\n\n")
            f.write("| Protocol | Count | Percentage |\n")
            f.write("|----------|-------|------------|\n")
            for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / stats['total_packets']) * 100
                f.write(f"| {proto} | {count} | {percentage:.1f}% |\n")
            f.write("\n")
            
            f.write("## Top Source IP Addresses\n\n")
            f.write("| IP Address | Packet Count |\n")
            f.write("|------------|-------------|\n")
            for ip, count in sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"| {ip} | {count} |\n")
            f.write("\n")
            
            if alerts:
                f.write("## Security Alerts\n\n")
                for i, alert in enumerate(alerts, 1):
                    f.write(f"### Alert {i}: {alert['type']}\n\n")
                    f.write(f"- **Severity:** {alert['severity']}\n")
                    f.write(f"- **Source:** {alert['source']}\n")
                    f.write(f"- **Details:** {alert['details']}\n\n")
            else:
                f.write("## Security Alerts\n\n")
                f.write("✅ No suspicious activity detected\n\n")
            
            f.write("\n---\n\n")
            f.write("*Report generated by NetSec Toolkit*\n")
        
        print(f"{Colors.GREEN}[+] Packet analysis exported to {filename}{Colors.END}")
    
    @staticmethod
    def export_vulnerability_scan(results, filename='vulnerability_scan.md'):
        """Export vulnerability scan to Markdown"""
        with open(filename, 'w') as f:
            f.write("# Vulnerability Scan Report\n\n")
            f.write(f"**Target:** {results['target']} ({results['ip_address']})\n")
            f.write(f"**Scan Date:** {results['scan_time']}\n")
            f.write(f"**Risk Score:** {results['risk_score']}/100\n\n")
            f.write("---\n\n")
            
            f.write("## Open Ports\n\n")
            for port in results['open_ports']:
                service = results['services'].get(port, {})
                f.write(f"- Port {port}: {service.get('service', 'Unknown')} {service.get('version', '')}\n")
            f.write("\n")
            
            if results['vulnerabilities']:
                f.write("## Vulnerabilities\n\n")
                for i, vuln in enumerate(results['vulnerabilities'], 1):
                    f.write(f"### {i}. {vuln['type']}\n")
                    f.write(f"**Severity:** {vuln['severity']}\n")
                    f.write(f"**Description:** {vuln['description']}\n")
                    if 'url' in vuln:
                        f.write(f"**URL:** {vuln['url']}\n")
                    if 'cve' in vuln:
                        f.write(f"**CVE:** {vuln['cve']}\n")
                    f.write("\n")
            
            if results['ssl_issues']:
                f.write("## SSL/TLS Issues\n\n")
                for i, issue in enumerate(results['ssl_issues'], 1):
                    f.write(f"### {i}. {issue['type']}\n")
                    f.write(f"**Severity:** {issue['severity']}\n")
                    f.write(f"**Description:** {issue['description']}\n\n")
            
            f.write("\n---\n\n")
            f.write("*Report generated by NetSec Toolkit*\n")
        
        print(f"{Colors.GREEN}[+] Vulnerability scan exported to {filename}{Colors.END}")
    
    @staticmethod
    def export_packets_csv(packets, filename='packets.csv'):
        """Export packets to CSV format"""
        with open(filename, 'w') as f:
            f.write("Timestamp,Protocol,Source IP,Dest IP,Src Port,Dest Port\n")
            
            for packet in packets:
                timestamp = packet['timestamp']
                proto = packet.get('protocol_name', 'Unknown')
                src_ip = packet['ip']['src'] if 'ip' in packet else 'N/A'
                dest_ip = packet['ip']['dest'] if 'ip' in packet else 'N/A'
                
                src_port = dest_port = 'N/A'
                
                if 'tcp' in packet:
                    src_port = packet['tcp']['src_port']
                    dest_port = packet['tcp']['dest_port']
                elif 'udp' in packet:
                    src_port = packet['udp']['src_port']
                    dest_port = packet['udp']['dest_port']
                
                f.write(f"{timestamp},{proto},{src_ip},{dest_ip},{src_port},{dest_port}\n")
        
        print(f"{Colors.GREEN}[+] Packets exported to {filename}{Colors.END}")

# ============================================================================
# MAIN INTERFACE
# ============================================================================

def packet_capture_mode(args):
    """Run packet capture mode"""
    print_action_banner("PACKET CAPTURE MODE ACTIVATED")
    
    capture = PacketCapture(max_packets=args.count)
    
    if not capture.create_socket():
        return
    
    capture.capture_packets()
    
    if not capture.packets:
        print(f"{Colors.RED}[!] No packets captured{Colors.END}")
        return
    
    print(f"\n{Colors.CYAN}[*] Analyzing captured packets...{Colors.END}")
    analyzer = PacketAnalyzer(capture.packets)
    
    stats = analyzer.generate_statistics()
    analyzer.display_statistics(stats)
    
    alerts = analyzer.detect_suspicious_activity()
    analyzer.display_alerts(alerts)
    
    if args.export:
        print_action_banner("EXPORTING RESULTS")
        exporter = ReportExporter()
        exporter.export_packet_analysis(capture.packets, stats, alerts, 'packet_analysis.md')
        exporter.export_packets_csv(capture.packets, 'packets.csv')
    
    print(f"\n{Colors.GREEN}[+] Packet capture analysis complete!{Colors.END}")

def vulnerability_scan_mode(args):
    """Run vulnerability scan mode"""
    print_action_banner("VULNERABILITY SCAN MODE ACTIVATED")
    
    # Parse port range
    ports = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    elif ',' in args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = [int(args.ports)]
    
    scanner = VulnerabilityScanner(args.target, ports=ports, web_scan=args.web_scan)
    scanner.run_full_scan()
    
    if args.export:
        print_action_banner("EXPORTING RESULTS")
        exporter = ReportExporter()
        exporter.export_vulnerability_scan(scanner.results, 'vulnerability_scan.md')
    
    print(f"\n{Colors.GREEN}[+] Vulnerability scan complete!{Colors.END}")

def full_assessment_mode(args):
    """Run full security assessment"""
    print_action_banner("FULL SECURITY ASSESSMENT MODE")
    print(f"{Colors.CYAN}Running comprehensive security analysis...{Colors.END}\n")
    
    # Phase 1: Vulnerability Scan
    print(f"{Colors.BOLD}{Colors.YELLOW}[Phase 1/2] Starting Vulnerability Scan{Colors.END}\n")
    vulnerability_scan_mode(args)
    
    # Phase 2: Packet Capture
    if args.packet_count and args.packet_count > 0:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[Phase 2/2] Starting Network Traffic Analysis{Colors.END}\n")
        args.count = args.packet_count
        packet_capture_mode(args)
    
    print_action_banner("FULL ASSESSMENT COMPLETE")
    print(f"{Colors.GREEN}✓ All security checks completed successfully!{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='NetSec Toolkit - Comprehensive Network Security Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''{Colors.CYAN}
═══════════════════════════════════════════════════════════════════════════
                              USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════{Colors.END}

{Colors.YELLOW}Packet Capture:{Colors.END}
  python netsec_toolkit.py -c --count 100 --export
  python netsec_toolkit.py -c --count 500
  
{Colors.YELLOW}Vulnerability Scan:{Colors.END}
  python netsec_toolkit.py -s -t example.com -p 1-1000 --export
  python netsec_toolkit.py -s -t 192.168.1.1 -p 80,443,8080
  python netsec_toolkit.py -s -t example.com -p 1-65535
  
{Colors.YELLOW}Full Security Assessment:{Colors.END}
  python netsec_toolkit.py -full -t example.com -p 1-1024 --packet-count 100 --export
  python netsec_toolkit.py -full -t example.com -p 80,443 --packet-count 50

{Colors.RED}WARNING: Only use on systems you own or have explicit permission to test!{Colors.END}
        '''
    )
    
    # Main operation flags
    parser.add_argument('-c', '--capture', action='store_true', 
                        help='Packet capture mode')
    parser.add_argument('-s', '--scan', action='store_true', 
                        help='Vulnerability scan mode')
    parser.add_argument('-full', '--full', action='store_true', 
                        help='Full security assessment (scan + capture)')
    
    # Packet capture options
    parser.add_argument('--count', type=int, 
                        help='Number of packets to capture')
    
    # Vulnerability scan options
    parser.add_argument('-t', '--target', 
                        help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', default='1-1024', 
                        help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-w', '--web-scan', action='store_true', default=True, 
                        help='Enable web vulnerability scanning')
    
    # Full assessment options
    parser.add_argument('--packet-count', type=int, default=0, 
                        help='Number of packets to capture in full mode')
    
    # Export options
    parser.add_argument('-e', '--export', action='store_true', 
                        help='Export results to files')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check if no mode selected
    if not (args.capture or args.scan or args.full):
        print(f"{Colors.YELLOW}[!] No mode selected. Use -h for help{Colors.END}\n")
        parser.print_help()
        sys.exit(1)
    
    # Authorization check
    print(f"{Colors.YELLOW}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.RED}IMPORTANT NOTICE{Colors.END}")
    print(f"{Colors.YELLOW}{'='*70}{Colors.END}")
    print("This tool requires administrator/root privileges for packet capture.")
    print("Only use on networks/systems you own or have permission to test.")
    print(f"{Colors.RED}Unauthorized use may be illegal.{Colors.END}\n")
    
    response = input(f"{Colors.BOLD}Do you have authorization? (yes/no): {Colors.END}")
    if response.lower() != 'yes':
        print(f"{Colors.RED}Operation cancelled. Please obtain proper authorization.{Colors.END}")
        sys.exit(0)
    
    try:
        if args.capture:
            packet_capture_mode(args)
        elif args.scan:
            if not args.target:
                print(f"{Colors.RED}[!] Error: Target (-t) required for scan mode{Colors.END}")
                sys.exit(1)
            vulnerability_scan_mode(args)
        elif args.full:
            if not args.target:
                print(f"{Colors.RED}[!] Error: Target (-t) required for full mode{Colors.END}")
                sys.exit(1)
            full_assessment_mode(args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Operation interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
