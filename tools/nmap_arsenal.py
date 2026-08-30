#!/usr/bin/env python3
"""
Nmap Arsenal - Comprehensive Nmap Command Generator for Attack Surface Framework.

Features:
- Scan type configurations (SYN, TCP, UDP, etc.)
- NSE (Nmap Scripting Engine) script categories
- Service/version detection
- OS fingerprinting
- Vulnerability scanning
- Evasion techniques
- Common port lists
- Timing templates
- Output formats

WARNING: Use only with proper authorization.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class ScanType(Enum):
    """Nmap scan types."""
    SYN_SCAN = "-sS"           # TCP SYN scan (stealth)
    TCP_CONNECT = "-sT"        # TCP connect scan
    UDP_SCAN = "-sU"           # UDP scan
    FIN_SCAN = "-sF"           # TCP FIN scan
    XMAS_SCAN = "-sX"          # Xmas scan (FIN, PSH, URG)
    NULL_SCAN = "-sN"          # Null scan (no flags)
    ACK_SCAN = "-sA"           # ACK scan (firewall rules)
    WINDOW_SCAN = "-sW"        # Window scan
    MAIMON_SCAN = "-sM"        # Maimon scan
    IDLE_SCAN = "-sI"          # Idle scan (zombie)
    IP_PROTOCOL = "-sO"        # IP protocol scan
    FTP_BOUNCE = "-b"          # FTP bounce scan
    PING_SCAN = "-sn"          # Ping scan (no port scan)
    LIST_SCAN = "-sL"          # List scan (DNS resolution only)


class TimingTemplate(Enum):
    """Nmap timing templates."""
    PARANOID = "-T0"    # IDS evasion, very slow
    SNEAKY = "-T1"      # IDS evasion, slow
    POLITE = "-T2"      # Slow down to use less bandwidth
    NORMAL = "-T3"      # Default
    AGGRESSIVE = "-T4"  # Assume fast network
    INSANE = "-T5"      # Very aggressive, may miss results


class OutputFormat(Enum):
    """Nmap output formats."""
    NORMAL = "-oN"      # Normal output
    XML = "-oX"         # XML output
    GREPABLE = "-oG"    # Grepable output
    ALL = "-oA"         # All formats


class NSECategory(Enum):
    """NSE script categories."""
    AUTH = "auth"                   # Authentication bypass
    BROADCAST = "broadcast"         # Discover hosts via broadcast
    BRUTE = "brute"                 # Brute force attacks
    DEFAULT = "default"             # Default scripts (-sC)
    DISCOVERY = "discovery"         # Service discovery
    DOS = "dos"                     # Denial of service
    EXPLOIT = "exploit"             # Exploitation scripts
    EXTERNAL = "external"           # External services
    FUZZER = "fuzzer"               # Fuzzing scripts
    INTRUSIVE = "intrusive"         # Intrusive scripts
    MALWARE = "malware"             # Malware detection
    SAFE = "safe"                   # Safe scripts
    VERSION = "version"             # Version detection
    VULN = "vuln"                   # Vulnerability detection


@dataclass
class PortList:
    """Common port lists for different scenarios."""
    
    # Top ports
    TOP_20 = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    TOP_100 = "--top-ports 100"
    TOP_1000 = "--top-ports 1000"
    
    # Service-specific ports
    WEB = "80,443,8080,8443,8000,8888,9000,9443"
    WEB_EXTENDED = "80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888,9000,9090,9443"
    
    DATABASE = "1433,1521,3306,5432,6379,9042,27017,27018,28017"
    DATABASE_EXTENDED = "1433,1521,1583,3050,3306,5432,5984,6379,7474,8529,9042,9200,11211,27017,27018,28017,50000"
    
    MAIL = "25,110,143,465,587,993,995,2525"
    
    FILE_SHARING = "20,21,22,69,111,137,138,139,445,873,2049,3260"
    
    REMOTE_ACCESS = "22,23,512,513,514,3389,5900,5901,5902"
    
    VOIP = "5060,5061,10000-20000"
    
    WINDOWS = "135,137,138,139,445,593,636,3268,3269,3389,5985,5986,9389"
    WINDOWS_DC = "53,88,135,139,389,445,464,593,636,3268,3269,5722,9389"
    
    LINUX_COMMON = "21,22,23,25,53,80,110,111,139,143,443,445,993,995,2049,3306,5432,5900,8080"
    
    IOT = "23,80,443,554,8080,8443,8883,1883,5683"
    
    CLOUD = "22,80,443,2375,2376,4243,6443,8443,9090,10250,10255"
    
    # Full range
    ALL_PORTS = "-p-"
    
    # Fast scan common ports
    FAST = "-F"  # Top 100 ports


@dataclass
class NSEScript:
    """NSE script information."""
    name: str
    category: NSECategory
    description: str
    args: Optional[str] = None
    risk_level: str = "medium"  # safe, medium, intrusive


class NmapArsenal:
    """Comprehensive Nmap command generator."""
    
    def __init__(self):
        self.scripts: list[NSEScript] = []
        self._load_vuln_scripts()
        self._load_discovery_scripts()
        self._load_brute_scripts()
        self._load_exploit_scripts()
        self._load_web_scripts()
        self._load_database_scripts()
        self._load_smb_scripts()
        self._load_ssh_scripts()
        self._load_ssl_scripts()
        self._load_dns_scripts()
        self._load_ftp_scripts()
        self._load_mail_scripts()
        self._load_snmp_scripts()
        self._load_ldap_scripts()
        self._load_misc_scripts()
    
    # ==================== VULNERABILITY SCRIPTS ====================
    def _load_vuln_scripts(self):
        """Load vulnerability detection scripts."""
        scripts = [
            # General vulnerability scanning
            ("vuln", NSECategory.VULN, "Run all vuln category scripts", None, "intrusive"),
            ("vulners", NSECategory.VULN, "CVE lookup via vulners.com API", None, "safe"),
            ("vulscan", NSECategory.VULN, "Offline CVE scanning (requires vulscan db)", None, "safe"),
            
            # Specific vulnerabilities
            ("smb-vuln-ms17-010", NSECategory.VULN, "EternalBlue SMB RCE check", None, "safe"),
            ("smb-vuln-ms08-067", NSECategory.VULN, "Conficker SMB RCE check", None, "safe"),
            ("smb-vuln-cve-2017-7494", NSECategory.VULN, "SambaCry RCE check", None, "safe"),
            ("smb-vuln-cve2009-3103", NSECategory.VULN, "SMBv2 DoS check", None, "safe"),
            ("smb-vuln-ms10-054", NSECategory.VULN, "SMB memory corruption", None, "safe"),
            ("smb-vuln-ms10-061", NSECategory.VULN, "Stuxnet print spooler", None, "safe"),
            ("smb-vuln-regsvc-dos", NSECategory.VULN, "Registry service DoS", None, "safe"),
            
            # SSL/TLS vulnerabilities
            ("ssl-heartbleed", NSECategory.VULN, "Heartbleed vulnerability check", None, "safe"),
            ("ssl-poodle", NSECategory.VULN, "POODLE vulnerability check", None, "safe"),
            ("ssl-ccs-injection", NSECategory.VULN, "CCS injection check", None, "safe"),
            ("ssl-dh-params", NSECategory.VULN, "Weak DH params (Logjam)", None, "safe"),
            ("sslv2-drown", NSECategory.VULN, "DROWN attack check", None, "safe"),
            
            # Web vulnerabilities
            ("http-vuln-cve2017-5638", NSECategory.VULN, "Apache Struts RCE", None, "intrusive"),
            ("http-vuln-cve2014-3704", NSECategory.VULN, "Drupalgeddon SQLi", None, "intrusive"),
            ("http-vuln-cve2017-1001000", NSECategory.VULN, "WordPress REST API", None, "safe"),
            ("http-shellshock", NSECategory.VULN, "Shellshock bash RCE", "http-shellshock.uri=/cgi-bin/", "intrusive"),
            
            # Other
            ("rmi-vuln-classloader", NSECategory.VULN, "Java RMI classloader", None, "safe"),
            ("rdp-vuln-ms12-020", NSECategory.VULN, "RDP DoS vulnerability", None, "safe"),
            ("ftp-vsftpd-backdoor", NSECategory.VULN, "vsftpd 2.3.4 backdoor", None, "safe"),
            ("distcc-cve2004-2687", NSECategory.VULN, "DistCC RCE", None, "intrusive"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== DISCOVERY SCRIPTS ====================
    def _load_discovery_scripts(self):
        """Load service discovery scripts."""
        scripts = [
            ("banner", NSECategory.DISCOVERY, "Grab service banners", None, "safe"),
            ("dns-brute", NSECategory.DISCOVERY, "DNS subdomain brute force", "dns-brute.threads=10", "safe"),
            ("dns-zone-transfer", NSECategory.DISCOVERY, "Attempt DNS zone transfer", None, "safe"),
            ("http-enum", NSECategory.DISCOVERY, "Enumerate web directories", None, "safe"),
            ("http-headers", NSECategory.DISCOVERY, "Get HTTP headers", None, "safe"),
            ("http-methods", NSECategory.DISCOVERY, "Enumerate HTTP methods", None, "safe"),
            ("http-robots.txt", NSECategory.DISCOVERY, "Get robots.txt", None, "safe"),
            ("http-sitemap-generator", NSECategory.DISCOVERY, "Generate sitemap", None, "safe"),
            ("http-vhosts", NSECategory.DISCOVERY, "Virtual host discovery", None, "safe"),
            ("http-waf-detect", NSECategory.DISCOVERY, "WAF detection", None, "safe"),
            ("http-waf-fingerprint", NSECategory.DISCOVERY, "WAF fingerprinting", None, "safe"),
            ("smb-os-discovery", NSECategory.DISCOVERY, "SMB OS detection", None, "safe"),
            ("smb-enum-domains", NSECategory.DISCOVERY, "SMB domain enumeration", None, "safe"),
            ("smb-enum-groups", NSECategory.DISCOVERY, "SMB group enumeration", None, "safe"),
            ("smb-enum-processes", NSECategory.DISCOVERY, "SMB process enumeration", None, "safe"),
            ("smb-enum-sessions", NSECategory.DISCOVERY, "SMB session enumeration", None, "safe"),
            ("smb-enum-shares", NSECategory.DISCOVERY, "SMB share enumeration", None, "safe"),
            ("smb-enum-users", NSECategory.DISCOVERY, "SMB user enumeration", None, "safe"),
            ("snmp-info", NSECategory.DISCOVERY, "SNMP system info", None, "safe"),
            ("snmp-interfaces", NSECategory.DISCOVERY, "SNMP interface info", None, "safe"),
            ("snmp-netstat", NSECategory.DISCOVERY, "SNMP netstat info", None, "safe"),
            ("snmp-processes", NSECategory.DISCOVERY, "SNMP process list", None, "safe"),
            ("snmp-sysdescr", NSECategory.DISCOVERY, "SNMP system description", None, "safe"),
            ("nbstat", NSECategory.DISCOVERY, "NetBIOS info", None, "safe"),
            ("rdp-enum-encryption", NSECategory.DISCOVERY, "RDP encryption level", None, "safe"),
            ("vnc-info", NSECategory.DISCOVERY, "VNC server info", None, "safe"),
            ("mysql-info", NSECategory.DISCOVERY, "MySQL server info", None, "safe"),
            ("ms-sql-info", NSECategory.DISCOVERY, "MSSQL server info", None, "safe"),
            ("oracle-tns-version", NSECategory.DISCOVERY, "Oracle TNS version", None, "safe"),
            ("mongodb-info", NSECategory.DISCOVERY, "MongoDB server info", None, "safe"),
            ("redis-info", NSECategory.DISCOVERY, "Redis server info", None, "safe"),
            ("memcached-info", NSECategory.DISCOVERY, "Memcached info", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== BRUTE FORCE SCRIPTS ====================
    def _load_brute_scripts(self):
        """Load brute force scripts."""
        scripts = [
            ("ftp-brute", NSECategory.BRUTE, "FTP brute force", None, "intrusive"),
            ("ssh-brute", NSECategory.BRUTE, "SSH brute force", None, "intrusive"),
            ("telnet-brute", NSECategory.BRUTE, "Telnet brute force", None, "intrusive"),
            ("http-brute", NSECategory.BRUTE, "HTTP basic auth brute", None, "intrusive"),
            ("http-form-brute", NSECategory.BRUTE, "HTTP form brute force", None, "intrusive"),
            ("mysql-brute", NSECategory.BRUTE, "MySQL brute force", None, "intrusive"),
            ("ms-sql-brute", NSECategory.BRUTE, "MSSQL brute force", None, "intrusive"),
            ("oracle-brute", NSECategory.BRUTE, "Oracle brute force", None, "intrusive"),
            ("pgsql-brute", NSECategory.BRUTE, "PostgreSQL brute force", None, "intrusive"),
            ("mongodb-brute", NSECategory.BRUTE, "MongoDB brute force", None, "intrusive"),
            ("redis-brute", NSECategory.BRUTE, "Redis brute force", None, "intrusive"),
            ("smb-brute", NSECategory.BRUTE, "SMB brute force", None, "intrusive"),
            ("snmp-brute", NSECategory.BRUTE, "SNMP community brute", None, "intrusive"),
            ("vnc-brute", NSECategory.BRUTE, "VNC brute force", None, "intrusive"),
            ("rdp-brute", NSECategory.BRUTE, "RDP brute force", None, "intrusive"),
            ("pop3-brute", NSECategory.BRUTE, "POP3 brute force", None, "intrusive"),
            ("imap-brute", NSECategory.BRUTE, "IMAP brute force", None, "intrusive"),
            ("smtp-brute", NSECategory.BRUTE, "SMTP brute force", None, "intrusive"),
            ("ldap-brute", NSECategory.BRUTE, "LDAP brute force", None, "intrusive"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== EXPLOIT SCRIPTS ====================
    def _load_exploit_scripts(self):
        """Load exploitation scripts."""
        scripts = [
            ("ftp-vsftpd-backdoor", NSECategory.EXPLOIT, "Exploit vsftpd backdoor", None, "intrusive"),
            ("irc-unrealircd-backdoor", NSECategory.EXPLOIT, "Exploit UnrealIRCd backdoor", None, "intrusive"),
            ("smtp-vuln-cve2010-4344", NSECategory.EXPLOIT, "Exim heap overflow", None, "intrusive"),
            ("http-slowloris-check", NSECategory.EXPLOIT, "Slowloris DoS check", None, "intrusive"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== WEB SCRIPTS ====================
    def _load_web_scripts(self):
        """Load web application scripts."""
        scripts = [
            ("http-title", NSECategory.DEFAULT, "Get page title", None, "safe"),
            ("http-server-header", NSECategory.DEFAULT, "Get server header", None, "safe"),
            ("http-favicon", NSECategory.DISCOVERY, "Get favicon hash", None, "safe"),
            ("http-git", NSECategory.DISCOVERY, "Check for .git exposure", None, "safe"),
            ("http-svn-enum", NSECategory.DISCOVERY, "Check for .svn exposure", None, "safe"),
            ("http-backup-finder", NSECategory.DISCOVERY, "Find backup files", None, "safe"),
            ("http-config-backup", NSECategory.DISCOVERY, "Find config backups", None, "safe"),
            ("http-php-version", NSECategory.DISCOVERY, "Detect PHP version", None, "safe"),
            ("http-wordpress-enum", NSECategory.DISCOVERY, "WordPress enumeration", None, "safe"),
            ("http-wordpress-users", NSECategory.DISCOVERY, "WordPress user enum", None, "safe"),
            ("http-drupal-enum", NSECategory.DISCOVERY, "Drupal enumeration", None, "safe"),
            ("http-joomla-brute", NSECategory.BRUTE, "Joomla admin brute", None, "intrusive"),
            ("http-sql-injection", NSECategory.VULN, "SQLi detection", None, "intrusive"),
            ("http-stored-xss", NSECategory.VULN, "Stored XSS detection", None, "intrusive"),
            ("http-dombased-xss", NSECategory.VULN, "DOM XSS detection", None, "intrusive"),
            ("http-csrf", NSECategory.VULN, "CSRF detection", None, "safe"),
            ("http-fileupload-exploiter", NSECategory.EXPLOIT, "File upload exploit", None, "intrusive"),
            ("http-put", NSECategory.VULN, "HTTP PUT method test", None, "intrusive"),
            ("http-trace", NSECategory.VULN, "HTTP TRACE/TRACK test", None, "safe"),
            ("http-iis-webdav-vuln", NSECategory.VULN, "IIS WebDAV vuln", None, "safe"),
            ("http-aspnet-debug", NSECategory.VULN, "ASP.NET debug mode", None, "safe"),
            ("http-cors", NSECategory.VULN, "CORS misconfiguration", None, "safe"),
            ("http-cookie-flags", NSECategory.VULN, "Cookie security flags", None, "safe"),
            ("http-security-headers", NSECategory.VULN, "Security headers check", None, "safe"),
            ("http-internal-ip-disclosure", NSECategory.VULN, "Internal IP disclosure", None, "safe"),
            ("http-proxy", NSECategory.DISCOVERY, "HTTP proxy detection", None, "safe"),
            ("http-open-proxy", NSECategory.VULN, "Open proxy check", None, "safe"),
            ("http-open-redirect", NSECategory.VULN, "Open redirect check", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== DATABASE SCRIPTS ====================
    def _load_database_scripts(self):
        """Load database scripts."""
        scripts = [
            ("mysql-databases", NSECategory.DISCOVERY, "List MySQL databases", None, "safe"),
            ("mysql-users", NSECategory.DISCOVERY, "List MySQL users", None, "safe"),
            ("mysql-variables", NSECategory.DISCOVERY, "Get MySQL variables", None, "safe"),
            ("mysql-audit", NSECategory.VULN, "MySQL security audit", None, "safe"),
            ("mysql-empty-password", NSECategory.VULN, "MySQL empty password", None, "safe"),
            ("mysql-vuln-cve2012-2122", NSECategory.VULN, "MySQL auth bypass", None, "safe"),
            
            ("ms-sql-tables", NSECategory.DISCOVERY, "List MSSQL tables", None, "safe"),
            ("ms-sql-hasdbaccess", NSECategory.DISCOVERY, "Check MSSQL DB access", None, "safe"),
            ("ms-sql-dump-hashes", NSECategory.DISCOVERY, "Dump MSSQL hashes", None, "intrusive"),
            ("ms-sql-xp-cmdshell", NSECategory.EXPLOIT, "MSSQL xp_cmdshell", None, "intrusive"),
            
            ("pgsql-brute", NSECategory.BRUTE, "PostgreSQL brute force", None, "intrusive"),
            
            ("oracle-sid-brute", NSECategory.BRUTE, "Oracle SID brute force", None, "intrusive"),
            ("oracle-enum-users", NSECategory.DISCOVERY, "Oracle user enumeration", None, "safe"),
            
            ("mongodb-databases", NSECategory.DISCOVERY, "List MongoDB databases", None, "safe"),
            
            ("redis-info", NSECategory.DISCOVERY, "Redis info", None, "safe"),
            ("couchdb-databases", NSECategory.DISCOVERY, "List CouchDB databases", None, "safe"),
            ("couchdb-stats", NSECategory.DISCOVERY, "CouchDB stats", None, "safe"),
            ("cassandra-info", NSECategory.DISCOVERY, "Cassandra info", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== SMB SCRIPTS ====================
    def _load_smb_scripts(self):
        """Load SMB scripts."""
        scripts = [
            ("smb-protocols", NSECategory.DISCOVERY, "SMB protocol versions", None, "safe"),
            ("smb-security-mode", NSECategory.DISCOVERY, "SMB security mode", None, "safe"),
            ("smb2-capabilities", NSECategory.DISCOVERY, "SMB2 capabilities", None, "safe"),
            ("smb2-security-mode", NSECategory.DISCOVERY, "SMB2 security mode", None, "safe"),
            ("smb2-time", NSECategory.DISCOVERY, "SMB2 server time", None, "safe"),
            ("smb-ls", NSECategory.DISCOVERY, "List SMB shares", "smb-ls.shares=C$", "safe"),
            ("smb-mbenum", NSECategory.DISCOVERY, "SMB master browser", None, "safe"),
            ("smb-print-text", NSECategory.INTRUSIVE, "Print to SMB printer", None, "intrusive"),
            ("smb-psexec", NSECategory.EXPLOIT, "SMB remote execution", None, "intrusive"),
            ("smb-system-info", NSECategory.DISCOVERY, "SMB system info", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== SSH SCRIPTS ====================
    def _load_ssh_scripts(self):
        """Load SSH scripts."""
        scripts = [
            ("ssh-hostkey", NSECategory.DISCOVERY, "SSH host key", None, "safe"),
            ("ssh-auth-methods", NSECategory.DISCOVERY, "SSH auth methods", None, "safe"),
            ("ssh2-enum-algos", NSECategory.DISCOVERY, "SSH2 algorithms", None, "safe"),
            ("ssh-publickey-acceptance", NSECategory.DISCOVERY, "SSH pubkey acceptance", None, "safe"),
            ("sshv1", NSECategory.VULN, "SSHv1 detection", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== SSL/TLS SCRIPTS ====================
    def _load_ssl_scripts(self):
        """Load SSL/TLS scripts."""
        scripts = [
            ("ssl-cert", NSECategory.DISCOVERY, "SSL certificate info", None, "safe"),
            ("ssl-date", NSECategory.DISCOVERY, "SSL date check", None, "safe"),
            ("ssl-enum-ciphers", NSECategory.DISCOVERY, "SSL cipher enumeration", None, "safe"),
            ("ssl-known-key", NSECategory.VULN, "Known weak SSL keys", None, "safe"),
            ("sslv2", NSECategory.VULN, "SSLv2 detection", None, "safe"),
            ("tls-alpn", NSECategory.DISCOVERY, "TLS ALPN protocols", None, "safe"),
            ("tls-nextprotoneg", NSECategory.DISCOVERY, "TLS NPN protocols", None, "safe"),
            ("tls-ticketbleed", NSECategory.VULN, "Ticketbleed vulnerability", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== DNS SCRIPTS ====================
    def _load_dns_scripts(self):
        """Load DNS scripts."""
        scripts = [
            ("dns-nsid", NSECategory.DISCOVERY, "DNS server ID", None, "safe"),
            ("dns-recursion", NSECategory.DISCOVERY, "DNS recursion check", None, "safe"),
            ("dns-service-discovery", NSECategory.DISCOVERY, "DNS service discovery", None, "safe"),
            ("dns-cache-snoop", NSECategory.DISCOVERY, "DNS cache snooping", None, "safe"),
            ("dns-random-srcport", NSECategory.VULN, "DNS random port check", None, "safe"),
            ("dns-random-txid", NSECategory.VULN, "DNS random TXID check", None, "safe"),
            ("dns-update", NSECategory.VULN, "DNS dynamic update", None, "intrusive"),
            ("dns-fuzz", NSECategory.FUZZER, "DNS fuzzing", None, "intrusive"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== FTP SCRIPTS ====================
    def _load_ftp_scripts(self):
        """Load FTP scripts."""
        scripts = [
            ("ftp-anon", NSECategory.DISCOVERY, "FTP anonymous login", None, "safe"),
            ("ftp-bounce", NSECategory.VULN, "FTP bounce attack", None, "safe"),
            ("ftp-libopie", NSECategory.VULN, "FTP libopie vuln", None, "safe"),
            ("ftp-proftpd-backdoor", NSECategory.VULN, "ProFTPD backdoor", None, "safe"),
            ("ftp-syst", NSECategory.DISCOVERY, "FTP SYST command", None, "safe"),
            ("tftp-enum", NSECategory.DISCOVERY, "TFTP file enumeration", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== MAIL SCRIPTS ====================
    def _load_mail_scripts(self):
        """Load mail server scripts."""
        scripts = [
            ("smtp-commands", NSECategory.DISCOVERY, "SMTP commands", None, "safe"),
            ("smtp-enum-users", NSECategory.DISCOVERY, "SMTP user enumeration", None, "safe"),
            ("smtp-ntlm-info", NSECategory.DISCOVERY, "SMTP NTLM info", None, "safe"),
            ("smtp-open-relay", NSECategory.VULN, "SMTP open relay", None, "safe"),
            ("smtp-strangeport", NSECategory.VULN, "SMTP on non-standard port", None, "safe"),
            
            ("pop3-capabilities", NSECategory.DISCOVERY, "POP3 capabilities", None, "safe"),
            ("pop3-ntlm-info", NSECategory.DISCOVERY, "POP3 NTLM info", None, "safe"),
            
            ("imap-capabilities", NSECategory.DISCOVERY, "IMAP capabilities", None, "safe"),
            ("imap-ntlm-info", NSECategory.DISCOVERY, "IMAP NTLM info", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== SNMP SCRIPTS ====================
    def _load_snmp_scripts(self):
        """Load SNMP scripts."""
        scripts = [
            ("snmp-info", NSECategory.DISCOVERY, "SNMP system info", None, "safe"),
            ("snmp-interfaces", NSECategory.DISCOVERY, "SNMP interfaces", None, "safe"),
            ("snmp-netstat", NSECategory.DISCOVERY, "SNMP network stats", None, "safe"),
            ("snmp-processes", NSECategory.DISCOVERY, "SNMP processes", None, "safe"),
            ("snmp-sysdescr", NSECategory.DISCOVERY, "SNMP description", None, "safe"),
            ("snmp-win32-services", NSECategory.DISCOVERY, "Windows services via SNMP", None, "safe"),
            ("snmp-win32-shares", NSECategory.DISCOVERY, "Windows shares via SNMP", None, "safe"),
            ("snmp-win32-software", NSECategory.DISCOVERY, "Windows software via SNMP", None, "safe"),
            ("snmp-win32-users", NSECategory.DISCOVERY, "Windows users via SNMP", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== LDAP SCRIPTS ====================
    def _load_ldap_scripts(self):
        """Load LDAP scripts."""
        scripts = [
            ("ldap-rootdse", NSECategory.DISCOVERY, "LDAP root DSE", None, "safe"),
            ("ldap-search", NSECategory.DISCOVERY, "LDAP search", None, "safe"),
            ("ldap-novell-getpass", NSECategory.VULN, "Novell LDAP getpass", None, "intrusive"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== MISC SCRIPTS ====================
    def _load_misc_scripts(self):
        """Load miscellaneous scripts."""
        scripts = [
            ("broadcast-dhcp-discover", NSECategory.BROADCAST, "DHCP discovery", None, "safe"),
            ("broadcast-dns-service-discovery", NSECategory.BROADCAST, "DNS-SD discovery", None, "safe"),
            ("broadcast-netbios-master-browser", NSECategory.BROADCAST, "NetBIOS master browser", None, "safe"),
            ("broadcast-upnp-info", NSECategory.BROADCAST, "UPnP discovery", None, "safe"),
            
            ("ntp-info", NSECategory.DISCOVERY, "NTP server info", None, "safe"),
            ("ntp-monlist", NSECategory.VULN, "NTP monlist amplification", None, "safe"),
            
            ("rpcinfo", NSECategory.DISCOVERY, "RPC portmapper info", None, "safe"),
            ("rpc-grind", NSECategory.DISCOVERY, "RPC grinding", None, "safe"),
            
            ("nfs-ls", NSECategory.DISCOVERY, "NFS share listing", None, "safe"),
            ("nfs-showmount", NSECategory.DISCOVERY, "NFS exports", None, "safe"),
            ("nfs-statfs", NSECategory.DISCOVERY, "NFS disk stats", None, "safe"),
            
            ("ajp-auth", NSECategory.DISCOVERY, "AJP authentication", None, "safe"),
            ("ajp-headers", NSECategory.DISCOVERY, "AJP headers", None, "safe"),
            ("ajp-methods", NSECategory.DISCOVERY, "AJP methods", None, "safe"),
            ("ajp-request", NSECategory.DISCOVERY, "AJP request", None, "safe"),
            
            ("x11-access", NSECategory.VULN, "X11 access check", None, "safe"),
            ("clock-skew", NSECategory.DISCOVERY, "Clock skew detection", None, "safe"),
            ("uptime-agent-info", NSECategory.DISCOVERY, "Uptime agent info", None, "safe"),
        ]
        
        for name, cat, desc, args, risk in scripts:
            self.scripts.append(NSEScript(name, cat, desc, args, risk))
    
    # ==================== COMMAND BUILDERS ====================
    
    def build_command(
        self,
        target: str,
        scan_type: ScanType = ScanType.SYN_SCAN,
        timing: TimingTemplate = TimingTemplate.NORMAL,
        ports: Optional[str] = None,
        scripts: Optional[list[str]] = None,
        script_args: Optional[str] = None,
        version_detection: bool = False,
        os_detection: bool = False,
        aggressive: bool = False,
        output_file: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.NORMAL,
        verbose: int = 0,
        no_ping: bool = False,
        service_detection: bool = False,
        extra_args: Optional[list[str]] = None,
    ) -> str:
        """Build a complete Nmap command."""
        cmd_parts = ["nmap"]
        
        # Scan type
        cmd_parts.append(scan_type.value)
        
        # Timing
        cmd_parts.append(timing.value)
        
        # Ports
        if ports:
            if ports.startswith("-"):
                cmd_parts.append(ports)
            else:
                cmd_parts.extend(["-p", ports])
        
        # Version detection
        if version_detection or aggressive:
            cmd_parts.append("-sV")
        
        # OS detection
        if os_detection or aggressive:
            cmd_parts.append("-O")
        
        # Aggressive mode
        if aggressive:
            cmd_parts.append("-A")
        
        # Service detection
        if service_detection:
            cmd_parts.append("-sC")  # Default scripts
        
        # Custom scripts
        if scripts:
            cmd_parts.append(f"--script={','.join(scripts)}")
        
        # Script arguments
        if script_args:
            cmd_parts.append(f"--script-args={script_args}")
        
        # No ping (treat host as up)
        if no_ping:
            cmd_parts.append("-Pn")
        
        # Verbose
        if verbose > 0:
            cmd_parts.append("-" + "v" * min(verbose, 3))
        
        # Output
        if output_file:
            cmd_parts.extend([output_format.value, output_file])
        
        # Extra arguments
        if extra_args:
            cmd_parts.extend(extra_args)
        
        # Target
        cmd_parts.append(target)
        
        return " ".join(cmd_parts)
    
    # ==================== PRESET COMMANDS ====================
    
    def quick_scan(self, target: str) -> str:
        """Quick scan of most common ports."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.AGGRESSIVE,
            ports=PortList.FAST,
            version_detection=True,
        )
    
    def full_scan(self, target: str, output: Optional[str] = None) -> str:
        """Full comprehensive scan."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.ALL_PORTS,
            version_detection=True,
            os_detection=True,
            service_detection=True,
            output_file=output,
            output_format=OutputFormat.ALL if output else OutputFormat.NORMAL,
        )
    
    def stealth_scan(self, target: str) -> str:
        """Stealthy scan for IDS evasion."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.SNEAKY,
            ports=PortList.TOP_100,
            no_ping=True,
            extra_args=["-f", "--mtu", "24", "-D", "RND:5"],
        )
    
    def vuln_scan(self, target: str) -> str:
        """Vulnerability scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.TOP_1000,
            version_detection=True,
            scripts=["vuln", "vulners"],
        )
    
    def web_scan(self, target: str) -> str:
        """Web application scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.WEB_EXTENDED,
            version_detection=True,
            scripts=[
                "http-enum", "http-headers", "http-methods", "http-title",
                "http-robots.txt", "http-git", "http-backup-finder",
                "http-waf-detect", "http-security-headers", "http-cookie-flags",
                "ssl-cert", "ssl-enum-ciphers",
            ],
        )
    
    def smb_scan(self, target: str) -> str:
        """SMB/Windows scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.WINDOWS,
            version_detection=True,
            scripts=[
                "smb-os-discovery", "smb-enum-shares", "smb-enum-users",
                "smb-protocols", "smb-security-mode", "smb-vuln-ms17-010",
                "smb-vuln-ms08-067",
            ],
        )
    
    def database_scan(self, target: str) -> str:
        """Database server scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.DATABASE_EXTENDED,
            version_detection=True,
            scripts=[
                "mysql-info", "mysql-databases", "mysql-empty-password",
                "ms-sql-info", "mongodb-info", "mongodb-databases",
                "redis-info", "couchdb-databases", "oracle-tns-version",
            ],
        )
    
    def dns_scan(self, target: str) -> str:
        """DNS server scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports="53",
            version_detection=True,
            scripts=[
                "dns-zone-transfer", "dns-brute", "dns-recursion",
                "dns-cache-snoop", "dns-nsid",
            ],
        )
    
    def ssl_scan(self, target: str) -> str:
        """SSL/TLS scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.SYN_SCAN,
            timing=TimingTemplate.NORMAL,
            ports="443,8443,9443",
            version_detection=True,
            scripts=[
                "ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed",
                "ssl-poodle", "ssl-ccs-injection", "ssl-dh-params",
                "sslv2-drown", "tls-ticketbleed",
            ],
        )
    
    def udp_scan(self, target: str) -> str:
        """UDP service scanning."""
        return self.build_command(
            target,
            scan_type=ScanType.UDP_SCAN,
            timing=TimingTemplate.NORMAL,
            ports="53,67,68,69,123,137,138,139,161,162,500,514,1900,4500,5353",
            version_detection=True,
            scripts=["snmp-info", "ntp-info", "dns-recursion", "tftp-enum"],
        )
    
    def firewall_detect(self, target: str) -> str:
        """Firewall/IDS detection."""
        return self.build_command(
            target,
            scan_type=ScanType.ACK_SCAN,
            timing=TimingTemplate.NORMAL,
            ports=PortList.TOP_100,
            extra_args=["--reason"],
        )
    
    # ==================== EVASION TECHNIQUES ====================
    
    def get_evasion_args(self, level: int = 1) -> list[str]:
        """Get evasion technique arguments based on level."""
        evasion_techniques = []
        
        if level >= 1:
            # Basic evasion
            evasion_techniques.extend(["-f"])  # Fragment packets
        
        if level >= 2:
            # Medium evasion
            evasion_techniques.extend([
                "--mtu", "24",           # Custom MTU
                "--data-length", "25",   # Append random data
            ])
        
        if level >= 3:
            # Advanced evasion
            evasion_techniques.extend([
                "-D", "RND:5",           # Decoy scans
                "--spoof-mac", "0",      # Random MAC
                "--badsum",              # Bad checksums
            ])
        
        if level >= 4:
            # Maximum evasion
            evasion_techniques.extend([
                "--scan-delay", "1s",    # Delay between probes
                "--max-retries", "1",    # Fewer retries
                "--randomize-hosts",     # Random host order
            ])
        
        return evasion_techniques
    
    # ==================== UTILITY METHODS ====================
    
    def get_scripts_by_category(self, category: NSECategory) -> list[NSEScript]:
        """Get all scripts in a category."""
        return [s for s in self.scripts if s.category == category]
    
    def get_safe_scripts(self) -> list[NSEScript]:
        """Get all safe scripts."""
        return [s for s in self.scripts if s.risk_level == "safe"]
    
    def get_intrusive_scripts(self) -> list[NSEScript]:
        """Get all intrusive scripts."""
        return [s for s in self.scripts if s.risk_level == "intrusive"]
    
    def search_scripts(self, keyword: str) -> list[NSEScript]:
        """Search scripts by keyword."""
        keyword = keyword.lower()
        return [
            s for s in self.scripts
            if keyword in s.name.lower() or keyword in s.description.lower()
        ]
    
    def stats(self) -> dict[str, int]:
        """Get script statistics."""
        stats = {"total": len(self.scripts)}
        for cat in NSECategory:
            stats[cat.name.lower()] = len(self.get_scripts_by_category(cat))
        for risk in ["safe", "medium", "intrusive"]:
            stats[f"risk_{risk}"] = len([s for s in self.scripts if s.risk_level == risk])
        return stats


# ==================== NMAP OUTPUT PARSER ====================

@dataclass
class NmapHost:
    """Parsed Nmap host result."""
    ip: str
    hostname: Optional[str] = None
    state: str = "unknown"
    os: Optional[str] = None
    ports: list[dict] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)


class NmapOutputParser:
    """Parse Nmap output (grepable format)."""
    
    @staticmethod
    def parse_grepable(content: str) -> list[NmapHost]:
        """Parse grepable output format."""
        hosts = []
        current_host = None
        
        for line in content.splitlines():
            if line.startswith("Host:"):
                parts = line.split("\t")
                ip_hostname = parts[0].replace("Host: ", "").strip()
                
                # Extract IP and hostname
                if "(" in ip_hostname:
                    ip = ip_hostname.split("(")[0].strip()
                    hostname = ip_hostname.split("(")[1].rstrip(")")
                else:
                    ip = ip_hostname
                    hostname = None
                
                current_host = NmapHost(ip=ip, hostname=hostname)
                
                # Parse ports
                for part in parts[1:]:
                    if part.startswith("Ports:"):
                        port_info = part.replace("Ports: ", "")
                        for port_str in port_info.split(", "):
                            if "/" in port_str:
                                port_parts = port_str.split("/")
                                current_host.ports.append({
                                    "port": port_parts[0],
                                    "state": port_parts[1],
                                    "protocol": port_parts[2] if len(port_parts) > 2 else "tcp",
                                    "service": port_parts[4] if len(port_parts) > 4 else "",
                                    "version": port_parts[6] if len(port_parts) > 6 else "",
                                })
                    elif part.startswith("OS:"):
                        current_host.os = part.replace("OS: ", "")
                
                hosts.append(current_host)
        
        return hosts


if __name__ == "__main__":
    arsenal = NmapArsenal()
    stats = arsenal.stats()
    
    print("=== Nmap Arsenal Statistics ===")
    print(f"Total NSE scripts: {stats['total']}")
    print("\nBy category:")
    for cat in NSECategory:
        count = stats.get(cat.name.lower(), 0)
        if count > 0:
            print(f"  {cat.name}: {count}")
    print("\nBy risk level:")
    for risk in ["safe", "medium", "intrusive"]:
        print(f"  {risk}: {stats[f'risk_{risk}']}")
    
    print("\n=== Sample Commands ===")
    print(f"Quick scan:    {arsenal.quick_scan('target.com')}")
    print(f"Stealth scan:  {arsenal.stealth_scan('target.com')}")
    print(f"Vuln scan:     {arsenal.vuln_scan('target.com')}")
    print(f"Web scan:      {arsenal.web_scan('target.com')}")
    print(f"SMB scan:      {arsenal.smb_scan('target.com')}")
