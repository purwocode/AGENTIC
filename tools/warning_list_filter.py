#!/usr/bin/env python3
"""
MISP Warning List Filter - False Positive Reduction
====================================================

Integrates MISP Warning Lists (https://github.com/MISP/misp-warninglists)
to reduce false positives in security scanning results.

Categories:
- Top domains (Alexa, Cisco Umbrella, Cloudflare Radar, Tranco)
- Cloud provider IPs (AWS, Azure, GCP, Oracle OCI)
- CDN IPs (Cloudflare, Akamai, Fastly, Bunny)
- Security scanner IPs (Shodan, Censys, Rapid7, Tenable)
- Public DNS resolvers
- RFC private ranges (1918, 5735, 6598)
- Common IOC false positives
- Empty file hashes
- Dynamic DNS domains
- URL shorteners
- Sinkholes

License: CC0 1.0 (Public Domain)
Source: MISP Project - misp-warninglists
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlparse


class WarningCategory(Enum):
    """Categories of warning lists."""
    TOP_DOMAIN = auto()          # Popular legitimate domains
    CLOUD_PROVIDER = auto()      # AWS, Azure, GCP, etc.
    CDN = auto()                 # Cloudflare, Akamai, Fastly
    SECURITY_SCANNER = auto()    # Shodan, Censys, Rapid7
    PUBLIC_DNS = auto()          # 8.8.8.8, 1.1.1.1, etc.
    PRIVATE_NETWORK = auto()     # RFC1918, RFC5735
    EMPTY_HASH = auto()          # Hashes of empty files
    COMMON_FP = auto()           # Known false positive hashes
    DYNAMIC_DNS = auto()         # Dynamic DNS providers
    URL_SHORTENER = auto()       # bit.ly, goo.gl, etc.
    SINKHOLE = auto()            # Known sinkholes
    DISPOSABLE_EMAIL = auto()    # Temporary email providers
    UNIVERSITY = auto()          # University domains
    BANK = auto()                # Bank domains
    SECURITY_VENDOR = auto()     # Security vendor blogs/domains
    MALWARE_ANALYSIS = auto()    # Automated malware analysis domains
    VPN = auto()                 # VPN provider ranges
    CAPTIVE_PORTAL = auto()      # Captive portal detection
    LINK_IN_BIO = auto()         # linktree, bio.link, etc.


@dataclass
class WarningMatch:
    """Result of a warning list match."""
    matched: bool
    category: WarningCategory | None = None
    list_name: str = ""
    description: str = ""
    confidence: float = 0.0  # 0.0-1.0, how confident this is a false positive


class MISPWarningListFilter:
    """
    Filter for reducing false positives using MISP Warning Lists.
    
    Usage:
        filter = MISPWarningListFilter()
        
        # Check if an IP is likely a false positive
        result = filter.check_ip("8.8.8.8")
        if result.matched:
            print(f"False positive: {result.description}")
        
        # Check a domain
        result = filter.check_domain("google.com")
        
        # Check a hash
        result = filter.check_hash("d41d8cd98f00b204e9800998ecf8427e")  # empty MD5
        
        # Check a URL
        result = filter.check_url("https://bit.ly/xyz")
    """
    
    def __init__(self):
        self._load_all_lists()
    
    def _load_all_lists(self):
        """Load all warning lists."""
        self._load_top_domains()
        self._load_cloud_providers()
        self._load_cdn_ranges()
        self._load_security_scanners()
        self._load_public_dns()
        self._load_private_networks()
        self._load_empty_hashes()
        self._load_common_fp_hashes()
        self._load_dynamic_dns()
        self._load_url_shorteners()
        self._load_sinkholes()
        self._load_disposable_email()
        self._load_security_vendors()
        self._load_malware_analysis()
        self._load_link_in_bio()
        self._load_captive_portals()
    
    # ===================== Top Domains =====================
    def _load_top_domains(self):
        """Load top domain lists (Alexa, Cisco, Cloudflare, Tranco)."""
        # Top 1000 domains from various sources (merged)
        self.top_domains = {
            # Google
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "googlevideo.com", "google.co.uk", "google.de", "google.fr", "google.es",
            "google.it", "google.co.jp", "google.com.br", "google.ru", "google.ca",
            "google.com.au", "google.co.in", "google.pl", "google.nl", "youtube.com",
            "youtube-nocookie.com", "ytimg.com", "ggpht.com", "gmail.com", "android.com",
            # Microsoft
            "microsoft.com", "windows.com", "office.com", "office365.com", "live.com",
            "outlook.com", "hotmail.com", "msn.com", "bing.com", "azure.com",
            "azureedge.net", "azurefd.net", "msedge.net", "microsoftonline.com",
            "windows.net", "windowsupdate.com", "skype.com", "linkedin.com", "github.com",
            # Amazon
            "amazon.com", "amazonaws.com", "cloudfront.net", "amazonaws.com", "aws.com",
            "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.fr", "amazon.es",
            "amazon.it", "amazon.ca", "amazon.in", "amazon.com.br", "amazon.com.au",
            # Apple
            "apple.com", "icloud.com", "apple-dns.net", "cdn-apple.com", "mzstatic.com",
            # Facebook/Meta
            "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com",
            "whatsapp.net", "messenger.com", "meta.com", "oculus.com",
            # Other major
            "twitter.com", "x.com", "twimg.com", "tiktok.com", "netflix.com",
            "nflxvideo.net", "spotify.com", "spotify.net", "reddit.com", "redditmedia.com",
            "wikipedia.org", "wikimedia.org", "yahoo.com", "yahoo.co.jp", "yimg.com",
            "zoom.us", "dropbox.com", "dropboxusercontent.com", "slack.com",
            "cloudflare.com", "cloudflare-dns.com", "akamai.com", "akamaiedge.net",
            "fastly.com", "fastly.net", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
            # Payment
            "paypal.com", "stripe.com", "braintreegateway.com", "paypalobjects.com",
            # News & Media
            "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "washingtonpost.com",
            "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com",
            # Tech
            "stackoverflow.com", "stackexchange.com", "docker.com", "docker.io",
            "npmjs.com", "pypi.org", "rubygems.org", "maven.org", "gradle.org",
            # CDN & Infrastructure
            "akamaihd.net", "edgekey.net", "akadns.net", "llnwd.net", "edgecastcdn.net",
            "stackpathdns.com", "stackpath.bootstrapcdn.com", "bootstrapcdn.com",
            "maxcdn.bootstrapcdn.com", "fontawesome.com", "fonts.googleapis.com",
        }
    
    # ===================== Cloud Providers =====================
    def _load_cloud_providers(self):
        """Load cloud provider IP ranges."""
        # Major cloud provider CIDR blocks (representative samples)
        self.cloud_cidrs = [
            # AWS (samples)
            "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8",
            "35.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8",
            # Azure
            "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/8",
            "40.64.0.0/10", "40.128.0.0/12", "51.0.0.0/8", "52.0.0.0/8",
            # GCP
            "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/12",
            "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13",
            # Oracle OCI
            "129.146.0.0/16", "130.35.0.0/16", "132.145.0.0/16", "134.70.0.0/17",
            "140.91.0.0/16", "147.154.0.0/16", "152.67.0.0/16",
            # DigitalOcean
            "104.131.0.0/16", "104.236.0.0/16", "138.68.0.0/16", "139.59.0.0/16",
            "142.93.0.0/16", "157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
            "161.35.0.0/16", "164.90.0.0/16", "165.22.0.0/16", "167.71.0.0/16",
            "167.172.0.0/16", "174.138.0.0/16", "178.128.0.0/16", "178.62.0.0/16",
            # Linode
            "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
            "66.175.0.0/16", "69.164.0.0/16", "72.14.176.0/20", "74.207.0.0/16",
            "96.126.96.0/19", "97.107.128.0/17", "139.144.0.0/16", "139.162.0.0/16",
            "143.42.0.0/16", "170.187.0.0/16", "172.104.0.0/15", "172.232.0.0/14",
            "173.230.128.0/17", "173.255.192.0/18", "178.79.128.0/17", "192.155.80.0/20",
            "194.195.208.0/20", "198.58.96.0/19", "198.74.48.0/20", "207.192.64.0/18",
            "212.71.232.0/21", "213.168.224.0/19", "213.219.36.0/22",
            # Vultr
            "45.32.0.0/15", "45.63.0.0/16", "45.76.0.0/15", "45.77.0.0/16",
            "64.156.0.0/14", "64.237.32.0/19", "66.42.32.0/19", "66.55.128.0/17",
            "78.141.192.0/18", "80.240.16.0/20", "95.179.128.0/17", "104.156.224.0/19",
            "104.207.128.0/18", "108.61.64.0/18", "136.244.64.0/18", "140.82.16.0/20",
            "144.202.0.0/16", "149.28.0.0/16", "155.138.128.0/17", "158.247.192.0/18",
            "167.179.64.0/18", "199.247.0.0/18", "207.148.64.0/18", "208.167.224.0/19",
            "209.250.224.0/19", "216.128.128.0/17", "217.69.0.0/17",
        ]
        self.cloud_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in self.cloud_cidrs]
    
    # ===================== CDN Ranges =====================
    def _load_cdn_ranges(self):
        """Load CDN IP ranges."""
        self.cdn_cidrs = [
            # Cloudflare
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
            "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
            "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
            # Akamai (samples)
            "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "104.64.0.0/10",
            # Fastly
            "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
            "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
            "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
            "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
            "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
        ]
        self.cdn_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in self.cdn_cidrs]
    
    # ===================== Security Scanners =====================
    def _load_security_scanners(self):
        """Load known security scanner IP ranges."""
        self.scanner_cidrs = [
            # Shodan
            "66.240.192.0/18", "71.6.128.0/17", "80.82.64.0/18", "93.120.27.0/24",
            "94.102.49.0/24", "198.20.64.0/18",
            # Censys
            "162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24", "167.94.146.0/24",
            "167.248.133.0/24",
            # Rapid7 (Project Sonar)
            "5.63.151.0/24", "71.6.128.0/17", "216.98.138.0/23",
            # Shadowserver
            "74.82.47.0/24", "184.105.139.0/24", "184.105.247.0/24", "216.218.206.0/24",
            # Tenable
            "13.59.252.0/23", "18.217.108.0/22", "34.201.0.0/16", "34.229.0.0/16",
            # Binary Edge
            "80.82.77.0/24", "80.82.78.0/24",
            # Alpha Strike Labs (AS208843)
            "193.163.125.0/24",
            # CIRCL scanning
            "185.194.93.0/24",
        ]
        self.scanner_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in self.scanner_cidrs]
    
    # ===================== Public DNS =====================
    def _load_public_dns(self):
        """Load public DNS resolver IPs."""
        self.public_dns = {
            # Google DNS
            "8.8.8.8", "8.8.4.4",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            # Cloudflare DNS
            "1.1.1.1", "1.0.0.1",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            # OpenDNS
            "208.67.222.222", "208.67.220.220", "208.67.222.220", "208.67.220.222",
            "2620:119:35::35", "2620:119:53::53",
            # Quad9
            "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
            "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10",
            # Comodo
            "8.26.56.26", "8.20.247.20",
            # DNS.Watch
            "84.200.69.80", "84.200.70.40",
            # Verisign
            "64.6.64.6", "64.6.65.6",
            # Level3
            "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
            # Norton ConnectSafe
            "199.85.126.10", "199.85.127.10",
            # AdGuard DNS
            "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141",
            # CleanBrowsing
            "185.228.168.168", "185.228.169.168",
            "185.228.168.9", "185.228.169.9",
            # Alternate DNS
            "76.76.19.19", "76.223.122.150",
        }
    
    # ===================== Private Networks (RFC) =====================
    def _load_private_networks(self):
        """Load RFC private/special network ranges."""
        self.private_cidrs = [
            # RFC 1918 - Private Networks
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            # RFC 5735 - Special Use
            "0.0.0.0/8",          # "This" network
            "127.0.0.0/8",        # Loopback
            "169.254.0.0/16",     # Link-local
            "192.0.0.0/24",       # IETF Protocol Assignments
            "192.0.2.0/24",       # TEST-NET-1
            "198.51.100.0/24",    # TEST-NET-2
            "203.0.113.0/24",     # TEST-NET-3
            "224.0.0.0/4",        # Multicast
            "240.0.0.0/4",        # Reserved for future use
            "255.255.255.255/32", # Broadcast
            # RFC 6598 - Shared Address Space (CGNAT)
            "100.64.0.0/10",
            # RFC 3849 - IPv6 Documentation
            "2001:db8::/32",
            # RFC 4291 - IPv6 Link-local
            "fe80::/10",
        ]
        self.private_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in self.private_cidrs]
    
    # ===================== Empty File Hashes =====================
    def _load_empty_hashes(self):
        """Load hashes of empty files."""
        self.empty_hashes = {
            # MD5
            "d41d8cd98f00b204e9800998ecf8427e",
            # SHA1
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            # SHA256
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            # SHA512
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            # SHA384
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        }
    
    # ===================== Common False Positive Hashes =====================
    def _load_common_fp_hashes(self):
        """Load known false positive hashes (from Florian Roth)."""
        self.fp_hashes = {
            # Common Windows files that appear in IOC lists
            "31d7bf2cd8c07f22dd1da44329a8f645",  # Empty PE header
            "8a2122e8162dbef04694b9c3e0b6cdee",  # Windows System file
            "db349b97c37d22f5ea1d1841e3c89eb4",  # Common installer
            "098f6bcd4621d373cade4e832627b4f6",  # MD5 of "test"
            "5d41402abc4b2a76b9719d911017c592",  # MD5 of "hello"
            "e99a18c428cb38d5f260853678922e03",  # MD5 of "abc123"
            "25f9e794323b453885f5181f1b624d0b",  # MD5 of "123456789"
            "b1a8db164e075415b7a99be72e3fe5a",   # MD5 of "111111"
            # EICAR test virus hashes (for AV testing)
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
            "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR SHA1
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
        }
    
    # ===================== Dynamic DNS =====================
    def _load_dynamic_dns(self):
        """Load dynamic DNS provider domains."""
        self.dynamic_dns_domains = {
            "dyndns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info",
            "ddns.net", "dynu.com", "afraid.org", "freedns.afraid.org",
            "changeip.com", "duckdns.org", "noip.com", "hopto.org",
            "zapto.org", "sytes.net", "ddnsfree.com", "serveftp.com",
            "servehttp.com", "servequake.com", "servecounterstrike.com",
            "servebbs.com", "servebeer.com", "serveblog.net", "servegame.com",
            "myftp.biz", "myftp.org", "myvnc.com", "gotdns.com", "gotdns.org",
            "dlinkddns.com", "tplinkdns.com", "asuscomm.com", "synology.me",
            "myqnapcloud.com", "i234.me", "mynetgear.com", "dvrdns.org",
        }
    
    # ===================== URL Shorteners =====================
    def _load_url_shorteners(self):
        """Load URL shortener domains."""
        self.url_shorteners = {
            "bit.ly", "bitly.com", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "j.mp", "tr.im", "cli.gs",
            "short.to", "budurl.com", "ping.fm", "twurl.nl", "su.pr",
            "tiny.cc", "snipurl.com", "sn.im", "v.gd", "cutt.ly",
            "rebrand.ly", "shorturl.at", "bl.ink", "short.io", "rb.gy",
            "s.id", "kortlink.dk", "kutt.it", "yourls.org", "polr.me",
            "t.ly", "rotf.lol", "shortcm.li", "1url.com", "hyperurl.co",
            "urlzs.com", "u.to", "qr.ae", "vzturl.com", "lnkd.in",
            "mcaf.ee", "amp.gs", "dlvr.it", "trib.al", "flip.it",
        }
    
    # ===================== Sinkholes =====================
    def _load_sinkholes(self):
        """Load known sinkhole domains and IPs."""
        self.sinkhole_domains = {
            "sinkhole.shadowserver.org", "sinkhole.tech", "sinkhole.ransomwaretracker.com",
            "rpz-sinkhole.org", "sinkhole.cert.pl", "sinkhole.dns-oarc.net",
        }
        self.sinkhole_ips = {
            "0.0.0.0", "127.0.0.1", "127.0.0.2", "127.1.2.3",
            "198.51.100.1", "203.0.113.1",  # Documentation addresses used as sinkholes
        }
    
    # ===================== Disposable Email =====================
    def _load_disposable_email(self):
        """Load disposable/temporary email domains."""
        self.disposable_email = {
            "guerrillamail.com", "guerrillamail.org", "guerrillamail.net",
            "guerrillamail.biz", "mailinator.com", "mailinator.net",
            "10minutemail.com", "10minutemail.net", "tempmail.com",
            "tempmail.net", "temp-mail.org", "throwaway.email",
            "maildrop.cc", "getairmail.com", "yopmail.com", "yopmail.fr",
            "getnada.com", "trashmail.com", "trashmail.net", "trashmail.org",
            "fakeinbox.com", "sharklasers.com", "spam4.me", "spamgourmet.com",
            "tempail.com", "discard.email", "discardmail.com", "mytemp.email",
            "mohmal.com", "tempr.email", "dispostable.com", "33mail.com",
            "mailnesia.com", "mailcatch.com", "inboxalias.com",
        }
    
    # ===================== Security Vendors =====================
    def _load_security_vendors(self):
        """Load security vendor/blog domains."""
        self.security_vendors = {
            # AV Vendors
            "virustotal.com", "kaspersky.com", "mcafee.com", "symantec.com",
            "norton.com", "avast.com", "avg.com", "bitdefender.com",
            "malwarebytes.com", "eset.com", "trendmicro.com", "sophos.com",
            "f-secure.com", "avira.com", "pandasecurity.com", "webroot.com",
            # Security Research
            "threatpost.com", "bleepingcomputer.com", "krebsonsecurity.com",
            "securityweek.com", "thehackernews.com", "darkreading.com",
            "securityaffairs.co", "cyberscoop.com", "recordedfuture.com",
            "mandiant.com", "fireeye.com", "crowdstrike.com", "paloaltonetworks.com",
            "fortinet.com", "checkpoint.com", "rapid7.com", "tenable.com",
            "qualys.com", "nessus.org", "snyk.io", "sonatype.com",
            # Threat Intel
            "otx.alienvault.com", "threatcrowd.org", "hybrid-analysis.com",
            "any.run", "joesandbox.com", "app.any.run", "triage.run",
        }
    
    # ===================== Malware Analysis =====================
    def _load_malware_analysis(self):
        """Load automated malware analysis service domains."""
        self.malware_analysis = {
            "virustotal.com", "hybrid-analysis.com", "any.run", "app.any.run",
            "joesandbox.com", "joesecurity.org", "intezer.com", "cuckoo.cert.ee",
            "malwr.com", "malwareanalysis.co", "filescan.io", "tria.ge",
            "analyze.intezer.com", "urlscan.io", "browserling.com",
            "hatching.io", "threatgrid.com", "vmray.com", "lastline.com",
            "proofpoint.com", "paloaltonetworks.com", "wildfire.paloaltonetworks.com",
        }
    
    # ===================== Link in Bio =====================
    def _load_link_in_bio(self):
        """Load link in bio service domains."""
        self.link_in_bio = {
            "linktr.ee", "linktree.com", "bio.link", "tap.bio", "lnk.bio",
            "beacons.ai", "later.com", "hoo.be", "linkin.bio", "campsite.bio",
            "allmylinks.com", "about.me", "carrd.co", "milkshake.app",
            "withkoji.com", "snipfeed.co", "stan.store", "solo.to",
        }
    
    # ===================== Captive Portals =====================
    def _load_captive_portals(self):
        """Load captive portal detection hostnames."""
        self.captive_portals = {
            # Apple
            "captive.apple.com", "www.apple.com",
            # Google/Android
            "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
            "clients3.google.com", "www.gstatic.com",
            # Microsoft/Windows
            "www.msftconnecttest.com", "msftncsi.com", "www.msftncsi.com",
            "ipv6.msftconnecttest.com", "dns.msftncsi.com",
            # Firefox
            "detectportal.firefox.com",
            # Ubuntu
            "connectivity-check.ubuntu.com",
            # Arch Linux
            "www.archlinux.org",
        }
    
    # ===================== Check Methods =====================
    def check_ip(self, ip: str) -> WarningMatch:
        """Check if an IP address is a likely false positive."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return WarningMatch(matched=False)
        
        # Check public DNS
        if ip in self.public_dns:
            return WarningMatch(
                matched=True,
                category=WarningCategory.PUBLIC_DNS,
                list_name="public-dns",
                description=f"Public DNS resolver: {ip}",
                confidence=0.95
            )
        
        # Check private networks
        for network in self.private_networks:
            if ip_obj in network:
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.PRIVATE_NETWORK,
                    list_name="rfc1918/rfc5735",
                    description=f"Private/special network: {network}",
                    confidence=0.99
                )
        
        # Check sinkholes
        if ip in self.sinkhole_ips:
            return WarningMatch(
                matched=True,
                category=WarningCategory.SINKHOLE,
                list_name="sinkholes",
                description=f"Known sinkhole IP: {ip}",
                confidence=0.90
            )
        
        # Check security scanners
        for network in self.scanner_networks:
            if ip_obj in network:
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.SECURITY_SCANNER,
                    list_name="security-scanners",
                    description=f"Security scanner IP range: {network}",
                    confidence=0.85
                )
        
        # Check CDN ranges
        for network in self.cdn_networks:
            if ip_obj in network:
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.CDN,
                    list_name="cdn-ranges",
                    description=f"CDN IP range: {network}",
                    confidence=0.70
                )
        
        # Check cloud providers
        for network in self.cloud_networks:
            if ip_obj in network:
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.CLOUD_PROVIDER,
                    list_name="cloud-providers",
                    description=f"Cloud provider IP range: {network}",
                    confidence=0.60
                )
        
        return WarningMatch(matched=False)
    
    def check_domain(self, domain: str) -> WarningMatch:
        """Check if a domain is a likely false positive."""
        domain = domain.lower().strip()
        
        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Check top domains (exact match)
        if domain in self.top_domains:
            return WarningMatch(
                matched=True,
                category=WarningCategory.TOP_DOMAIN,
                list_name="top-domains",
                description=f"Top legitimate domain: {domain}",
                confidence=0.95
            )
        
        # Check if subdomain of top domain
        for top in self.top_domains:
            if domain.endswith("." + top):
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.TOP_DOMAIN,
                    list_name="top-domains",
                    description=f"Subdomain of top domain: {top}",
                    confidence=0.85
                )
        
        # Check captive portals
        if domain in self.captive_portals:
            return WarningMatch(
                matched=True,
                category=WarningCategory.CAPTIVE_PORTAL,
                list_name="captive-portals",
                description=f"Captive portal detection: {domain}",
                confidence=0.95
            )
        
        # Check URL shorteners
        if domain in self.url_shorteners:
            return WarningMatch(
                matched=True,
                category=WarningCategory.URL_SHORTENER,
                list_name="url-shorteners",
                description=f"URL shortener: {domain}",
                confidence=0.50  # Lower - could be malicious shortened URL
            )
        
        # Check dynamic DNS
        for ddns in self.dynamic_dns_domains:
            if domain == ddns or domain.endswith("." + ddns):
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.DYNAMIC_DNS,
                    list_name="dynamic-dns",
                    description=f"Dynamic DNS domain: {ddns}",
                    confidence=0.40  # Lower - often used by malware
                )
        
        # Check disposable email
        if domain in self.disposable_email:
            return WarningMatch(
                matched=True,
                category=WarningCategory.DISPOSABLE_EMAIL,
                list_name="disposable-email",
                description=f"Disposable email provider: {domain}",
                confidence=0.30  # Lower - could indicate suspicious activity
            )
        
        # Check security vendors
        if domain in self.security_vendors:
            return WarningMatch(
                matched=True,
                category=WarningCategory.SECURITY_VENDOR,
                list_name="security-vendors",
                description=f"Security vendor domain: {domain}",
                confidence=0.95
            )
        
        # Check malware analysis
        if domain in self.malware_analysis:
            return WarningMatch(
                matched=True,
                category=WarningCategory.MALWARE_ANALYSIS,
                list_name="malware-analysis",
                description=f"Malware analysis service: {domain}",
                confidence=0.95
            )
        
        # Check sinkholes
        if domain in self.sinkhole_domains:
            return WarningMatch(
                matched=True,
                category=WarningCategory.SINKHOLE,
                list_name="sinkholes",
                description=f"Known sinkhole domain: {domain}",
                confidence=0.90
            )
        
        # Check link in bio
        if domain in self.link_in_bio:
            return WarningMatch(
                matched=True,
                category=WarningCategory.LINK_IN_BIO,
                list_name="link-in-bio",
                description=f"Link in bio service: {domain}",
                confidence=0.50
            )
        
        return WarningMatch(matched=False)
    
    def check_hash(self, file_hash: str) -> WarningMatch:
        """Check if a file hash is a likely false positive."""
        file_hash = file_hash.lower().strip()
        
        # Check empty hashes
        if file_hash in self.empty_hashes:
            return WarningMatch(
                matched=True,
                category=WarningCategory.EMPTY_HASH,
                list_name="empty-hashes",
                description="Hash of empty file",
                confidence=0.99
            )
        
        # Check common false positive hashes
        if file_hash in self.fp_hashes:
            return WarningMatch(
                matched=True,
                category=WarningCategory.COMMON_FP,
                list_name="common-ioc-false-positive",
                description="Known false positive hash",
                confidence=0.85
            )
        
        return WarningMatch(matched=False)
    
    def check_url(self, url: str) -> WarningMatch:
        """Check if a URL is a likely false positive."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if ":" in domain:  # Remove port
                domain = domain.split(":")[0]
            
            return self.check_domain(domain)
        except Exception:
            return WarningMatch(matched=False)
    
    def check_email(self, email: str) -> WarningMatch:
        """Check if an email domain is suspicious (disposable)."""
        try:
            domain = email.split("@")[1].lower()
            
            if domain in self.disposable_email:
                return WarningMatch(
                    matched=True,
                    category=WarningCategory.DISPOSABLE_EMAIL,
                    list_name="disposable-email",
                    description=f"Disposable email provider: {domain}",
                    confidence=0.70
                )
            
            return self.check_domain(domain)
        except Exception:
            return WarningMatch(matched=False)
    
    def check_indicator(self, indicator: str, indicator_type: str = "auto") -> WarningMatch:
        """
        Check any indicator type against warning lists.
        
        Args:
            indicator: The indicator to check
            indicator_type: One of "ip", "domain", "url", "hash", "email", or "auto"
        
        Returns:
            WarningMatch with result
        """
        if indicator_type == "auto":
            indicator_type = self._detect_type(indicator)
        
        if indicator_type == "ip":
            return self.check_ip(indicator)
        elif indicator_type == "domain":
            return self.check_domain(indicator)
        elif indicator_type == "url":
            return self.check_url(indicator)
        elif indicator_type == "hash":
            return self.check_hash(indicator)
        elif indicator_type == "email":
            return self.check_email(indicator)
        else:
            return WarningMatch(matched=False)
    
    def _detect_type(self, indicator: str) -> str:
        """Auto-detect indicator type."""
        indicator = indicator.strip()
        
        # Check if IP
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass
        
        # Check if URL
        if indicator.startswith(("http://", "https://", "ftp://")):
            return "url"
        
        # Check if email
        if "@" in indicator and "." in indicator.split("@")[-1]:
            return "email"
        
        # Check if hash (MD5, SHA1, SHA256, SHA512)
        if re.match(r"^[a-fA-F0-9]{32}$", indicator):  # MD5
            return "hash"
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):  # SHA1
            return "hash"
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):  # SHA256
            return "hash"
        if re.match(r"^[a-fA-F0-9]{128}$", indicator):  # SHA512
            return "hash"
        
        # Default to domain
        return "domain"
    
    def filter_findings(self, findings: list[dict], 
                       min_confidence: float = 0.5) -> tuple[list[dict], list[dict]]:
        """
        Filter a list of findings, separating likely false positives.
        
        Args:
            findings: List of finding dictionaries with 'indicator' and optionally 'type' keys
            min_confidence: Minimum confidence to consider as false positive (0.0-1.0)
        
        Returns:
            Tuple of (valid_findings, false_positives)
        """
        valid = []
        fps = []
        
        for finding in findings:
            indicator = finding.get("indicator", finding.get("value", ""))
            ind_type = finding.get("type", "auto")
            
            result = self.check_indicator(indicator, ind_type)
            
            if result.matched and result.confidence >= min_confidence:
                finding["fp_reason"] = result.description
                finding["fp_confidence"] = result.confidence
                finding["fp_category"] = result.category.name if result.category else None
                fps.append(finding)
            else:
                valid.append(finding)
        
        return valid, fps
    
    def stats(self) -> dict[str, int]:
        """Get statistics about loaded warning lists."""
        return {
            "top_domains": len(self.top_domains),
            "cloud_cidrs": len(self.cloud_cidrs),
            "cdn_cidrs": len(self.cdn_cidrs),
            "scanner_cidrs": len(self.scanner_cidrs),
            "public_dns": len(self.public_dns),
            "private_cidrs": len(self.private_cidrs),
            "empty_hashes": len(self.empty_hashes),
            "fp_hashes": len(self.fp_hashes),
            "dynamic_dns": len(self.dynamic_dns_domains),
            "url_shorteners": len(self.url_shorteners),
            "sinkhole_domains": len(self.sinkhole_domains),
            "sinkhole_ips": len(self.sinkhole_ips),
            "disposable_email": len(self.disposable_email),
            "security_vendors": len(self.security_vendors),
            "malware_analysis": len(self.malware_analysis),
            "link_in_bio": len(self.link_in_bio),
            "captive_portals": len(self.captive_portals),
        }


# Convenience function
def is_likely_false_positive(indicator: str, indicator_type: str = "auto") -> bool:
    """Quick check if an indicator is likely a false positive."""
    filter = MISPWarningListFilter()
    result = filter.check_indicator(indicator, indicator_type)
    return result.matched and result.confidence >= 0.5


if __name__ == "__main__":
    # Demo usage
    filter = MISPWarningListFilter()
    
    print("MISP Warning List Filter - Statistics")
    print("=" * 50)
    for key, value in filter.stats().items():
        print(f"  {key}: {value}")
    
    print("\n\nTest Checks:")
    print("=" * 50)
    
    # Test IPs
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "71.6.128.1"]
    for ip in test_ips:
        result = filter.check_ip(ip)
        status = f"FP: {result.description}" if result.matched else "OK"
        print(f"  IP {ip}: {status}")
    
    # Test domains
    test_domains = ["google.com", "bit.ly", "evil-malware.com", "virustotal.com", "duckdns.org"]
    for domain in test_domains:
        result = filter.check_domain(domain)
        status = f"FP: {result.description}" if result.matched else "OK"
        print(f"  Domain {domain}: {status}")
    
    # Test hashes
    test_hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",  # Empty MD5
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR
        "5d41402abc4b2a76b9719d911017c592",  # "hello"
        "abc123def456",  # Random (invalid)
    ]
    for h in test_hashes:
        result = filter.check_hash(h)
        status = f"FP: {result.description}" if result.matched else "OK"
        print(f"  Hash {h[:16]}...: {status}")
