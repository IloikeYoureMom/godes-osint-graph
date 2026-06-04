"""
OSINT Enrichment Engine
───────────────────────
Server-side enrichment for entity types.
Discovers carrier info, MX records, breach checks, OSINT links, etc.
"""

import re
import hashlib
import json
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse

# ─── Israeli Phone Carrier Prefixes ──────────────────────────────

ISRAELI_MOBILE_PREFIXES = {
    '050': 'Pelephone',
    '052': 'Cellcom',
    '053': 'HOT Mobile / Cellcom',
    '054': 'Partner (Orange)',
    '055': 'Ituran / MVNO',
    '056': 'Wataniya / Golan Telecom',
    '058': 'Golan Telecom / HOT Mobile',
    '059': 'Mirs (narrowband)',
}

ISRAELI_LANDLINE_AREA_CODES = {
    '02': 'Jerusalem & surroundings',
    '03': 'Tel Aviv & central area',
    '04': 'Haifa & northern area',
    '08': 'Southern area',
    '09': 'Sharon area',
}

# ─── Helpers ────────────────────────────────────────────────────

def _clean_phone(phone: str) -> str:
    """Strip everything except digits and leading +/0."""
    cleaned = re.sub(r'[^\d+]', '', phone)
    # If it starts with +972, convert to 0
    if cleaned.startswith('+972'):
        cleaned = '0' + cleaned[4:]
    return cleaned


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest().upper()


def _http_get(url: str, timeout: int = 5) -> str | None:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'OSINT-Graph/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8')
    except Exception:
        return None


def _check_mx(domain: str) -> list[str]:
    """Check MX records for a domain using dnspython."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).rstrip('.') for r in answers]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════
#  Phone Number Enrichment
# ══════════════════════════════════════════════════════════════════

def enrich_phone(phone: str) -> dict:
    result = {
        'type': 'phone_number',
        'value': phone,
        'intel': [],
        'links': [],
        'tags': [],
    }

    cleaned = _clean_phone(phone)
    if not cleaned:
        result['intel'].append({'label': 'Status', 'value': 'Invalid phone number format'})
        return result

    # Format check
    is_israeli = cleaned.startswith('0') and len(cleaned) in (9, 10)
    if not is_israeli:
        result['intel'].append({'label': 'Status', 'value': 'Not an Israeli phone number (expected 0XX-XXXXXXX)'})
        return result

    result['intel'].append({'label': 'Formatted', 'value': f'{cleaned[:3]}-{cleaned[3:]}'})

    # Detect prefix
    prefix = cleaned[:3]

    if prefix in ISRAELI_MOBILE_PREFIXES:
        result['intel'].append({'label': 'Type', 'value': ' Mobile'})
        result['intel'].append({'label': 'Carrier', 'value': ISRAELI_MOBILE_PREFIXES[prefix]})
        result['tags'].append('mobile')
        result['tags'].append(ISRAELI_MOBILE_PREFIXES[prefix].lower().split('/')[0].strip().replace(' ', '_'))
    elif prefix in ISRAELI_LANDLINE_AREA_CODES:
        result['intel'].append({'label': 'Type', 'value': ' Landline'})
        result['intel'].append({'label': 'Area', 'value': ISRAELI_LANDLINE_AREA_CODES[prefix]})
        result['tags'].append('landline')
    else:
        result['intel'].append({'label': 'Type', 'value': ' Unknown prefix'})

    # OSINT lookup links
    result['links'].append({'title': 'Check on 144 (Israeli directory)', 'url': f'https://www.144.co.il/Search/PhoneSearch?phone={cleaned}'})
    result['links'].append({'title': 'Check on Bezeg International', 'url': f'https://www.bizcom.co.il/search?q={cleaned}'})
    result['links'].append({'title': 'Search on Google', 'url': f'https://www.google.com/search?q={cleaned}'})
    result['links'].append({'title': 'Search on TrueCaller (web)', 'url': f'https://www.truecaller.com/search/il/{cleaned}'})

    return result


# ══════════════════════════════════════════════════════════════════
#  Email Enrichment
# ══════════════════════════════════════════════════════════════════

COMMON_EMAIL_PROVIDERS = {
    'gmail.com': 'Google Gmail',
    'yahoo.com': 'Yahoo Mail',
    'yahoo.co.il': 'Yahoo Mail Israel',
    'hotmail.com': 'Microsoft Hotmail',
    'outlook.com': 'Microsoft Outlook',
    'live.com': 'Microsoft Live',
    'walla.co.il': 'Walla! Mail',
    '013.net': '013 Netvision',
    'netvision.net.il': 'Netvision',
    'bezeqint.net': 'Bezeq International',
    'smile.net.il': 'Smile (012)',
    'zahav.net.il': 'Zahav',
    'actcom.net.il': 'Actcom',
    'barak.net.il': 'Barak',
    '012.net.il': '012 Smile',
    'post.bgu.ac.il': 'BGU University',
    'mail.tau.ac.il': 'Tel Aviv University',
    'mail.huji.ac.il': 'Hebrew University',
    'icloud.com': 'Apple iCloud',
    'proton.me': 'ProtonMail',
    'protonmail.com': 'ProtonMail',
}


def enrich_email(email: str) -> dict:
    result = {
        'type': 'email',
        'value': email,
        'intel': [],
        'links': [],
        'tags': [],
    }

    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        result['intel'].append({'label': 'Status', 'value': 'Invalid email format'})
        return result

    result['intel'].append({'label': 'Status', 'value': ' Valid format'})

    # Extract parts
    local_part, domain = email.split('@')
    result['intel'].append({'label': 'Domain', 'value': domain})

    # Check if common provider
    provider = COMMON_EMAIL_PROVIDERS.get(domain)
    if provider:
        result['intel'].append({'label': 'Provider', 'value': provider})
        result['tags'].append(domain.split('.')[0])
    else:
        result['tags'].append('custom_domain')

    # Check domain for common patterns
    if domain.endswith('.il'):
        result['intel'].append({'label': 'Country', 'value': ' Israel (.il)'})
        result['tags'].append('israeli')

    # Email pattern analysis
    if re.match(r'^[a-z]+\.[a-z]+@', email):
        result['intel'].append({'label': 'Pattern', 'value': 'First.Last name pattern'})
    elif re.match(r'^[a-z]+\d+@', email):
        result['intel'].append({'label': 'Pattern', 'value': 'Name + number pattern'})

    # MX record check
    mx_servers = _check_mx(domain)
    if mx_servers:
        result['intel'].append({'label': 'MX Servers', 'value': ', '.join(mx_servers[:3])})
        result['intel'].append({'label': 'Email Server', 'value': ' Active (MX records found)'})
    else:
        result['intel'].append({'label': 'Email Server', 'value': ' No MX records — domain may not receive email'})

    # HaveIBeenPwned check
    try:
        sha1_hash = _sha1(email)
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        resp = _http_get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if resp:
            breached = suffix in resp
            if breached:
                result['intel'].append({'label': 'Breach Check', 'value': ' Found in data breaches! Change password immediately.'})
                result['tags'].append('breached')
            else:
                result['intel'].append({'label': 'Breach Check', 'value': ' Not found in known breaches'})
        else:
            result['intel'].append({'label': 'Breach Check', 'value': ' Could not check (API unavailable)'})
    except Exception:
        result['intel'].append({'label': 'Breach Check', 'value': ' Could not check'})

    # OSINT lookup links
    result['links'].append({'title': 'Search on Google', 'url': f'https://www.google.com/search?q={email}'})
    result['links'].append({'title': 'Check on Hunter.io (email verification)', 'url': f'https://hunter.io/email-verifier/{email}'})
    result['links'].append({'title': 'Check on EmailRep.io', 'url': f'https://emailrep.io/{email}'})
    result['links'].append({'title': 'Check on HaveIBeenPwned', 'url': f'https://haveibeenpwned.com/account/{email}'})
    result['links'].append({'title': 'Search on Pipl (people search)', 'url': f'https://pipl.com/search/?q={email}'})

    return result


# ══════════════════════════════════════════════════════════════════
#  Domain / URL Enrichment
# ══════════════════════════════════════════════════════════════════

def enrich_domain(domain_or_url: str) -> dict:
    result = {
        'type': 'domain',
        'value': domain_or_url,
        'intel': [],
        'links': [],
        'tags': [],
    }

    # Extract domain from URL if needed
    if domain_or_url.startswith('http'):
        parsed = urlparse(domain_or_url)
        domain = parsed.netloc.lower()
    else:
        domain = domain_or_url.strip().lower()

    # Remove www. prefix for cleaner display
    clean_domain = re.sub(r'^www\.', '', domain)

    result['intel'].append({'label': 'Domain', 'value': clean_domain})

    # Try to resolve DNS
    try:
        ip = socket.gethostbyname(clean_domain)
        result['intel'].append({'label': 'IP Address', 'value': ip})
        result['intel'].append({'label': 'DNS', 'value': ' Resolves successfully'})
    except socket.gaierror:
        result['intel'].append({'label': 'DNS', 'value': ' Domain does not resolve'})
        return result

    # TLD info
    tld = clean_domain.split('.')[-1]
    if tld == 'il':
        result['intel'].append({'label': 'Country', 'value': ' Israel (.il)'})
        result['tags'].append('israeli')
    elif tld in ('com', 'org', 'net'):
        result['intel'].append({'label': 'TLD', 'value': f'.{tld} (global)'})

    # MX check
    mx_servers = _check_mx(clean_domain)
    if mx_servers:
        result['intel'].append({'label': 'MX Servers', 'value': f'{len(mx_servers)} mail server(s)'})
    else:
        result['intel'].append({'label': 'MX Servers', 'value': 'No mail servers (may not handle email)'})

    # Check for common technologies (simple patterns in domain)
    subdomains = domain.split('.')
    if len(subdomains) > 2:
        result['intel'].append({'label': 'Subdomain', 'value': subdomains[0]})

    # OSINT lookup links
    result['links'].append({'title': 'Check on VirusTotal', 'url': f'https://www.virustotal.com/gui/domain/{clean_domain}'})
    result['links'].append({'title': 'WHOIS Lookup', 'url': f'https://www.whois.com/whois/{clean_domain}'})
    result['links'].append({'title': 'Check on SecurityTrails (DNS history)', 'url': f'https://securitytrails.com/domain/{clean_domain}'})
    result['links'].append({'title': 'Check on crt.sh (SSL certificates)', 'url': f'https://crt.sh/?q={clean_domain}'})
    result['links'].append({'title': 'Check on URLScan.io', 'url': f'https://urlscan.io/search/#{clean_domain}'})
    result['links'].append({'title': 'Check on Shodan', 'url': f'https://www.shodan.io/search?query={ip}'})

    return result


# ══════════════════════════════════════════════════════════════════
#  Username Enrichment
# ══════════════════════════════════════════════════════════════════

SOCIAL_SEARCH_URLS = [
    ('TikTok', 'https://www.tiktok.com/@{username}'),
    ('Instagram', 'https://www.instagram.com/{username}/'),
    ('Twitter / X', 'https://twitter.com/{username}'),
    ('Facebook', 'https://www.facebook.com/{username}'),
    ('LinkedIn', 'https://www.linkedin.com/in/{username}/'),
    ('YouTube', 'https://www.youtube.com/@{username}'),
    ('GitHub', 'https://github.com/{username}'),
    ('Reddit', 'https://www.reddit.com/user/{username}'),
    ('Snapchat', 'https://www.snapchat.com/add/{username}'),
    ('Telegram', 'https://t.me/{username}'),
    ('Discord', 'https://discord.com/users/{username}'),
    ('Pinterest', 'https://www.pinterest.com/{username}/'),
    ('Twitch', 'https://www.twitch.tv/{username}'),
    ('Steam', 'https://steamcommunity.com/id/{username}'),
    ('Medium', 'https://medium.com/@{username}'),
    ('Check on WhatIsMyName', 'https://whatsmyname.app/?q={username}'),
    ('Check on Sherlock', 'https://sherlock-eye.com/username/{username}'),
]


def enrich_username(username: str) -> dict:
    result = {
        'type': 'username',
        'value': username,
        'intel': [],
        'links': [],
        'tags': [],
    }

    username = username.strip()
    if not username or len(username) < 2:
        result['intel'].append({'label': 'Status', 'value': 'Username too short'})
        return result

    result['intel'].append({'label': 'Status', 'value': f'Username: "{username}"'})
    result['intel'].append({'label': 'Length', 'value': f'{len(username)} characters'})

    # Character analysis
    if re.match(r'^[a-zA-Z]+$', username):
        result['intel'].append({'label': 'Pattern', 'value': 'Letters only'})
    elif re.match(r'^[a-zA-Z0-9_]+$', username):
        result['intel'].append({'label': 'Pattern', 'value': 'Alphanumeric + underscore'})
    elif re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', username):
        result['intel'].append({'label': 'Pattern', 'value': 'First.Last pattern (likely real name)'})

    # Check if it looks like a real name
    if re.match(r'^[A-Z][a-z]+[ _\.][A-Z][a-z]+$', username):
        result['intel'].append({'label': 'Name Guess', 'value': ' Looks like a real name'})
        result['tags'].append('possible_real_name')

    # Generate search links for all major platforms
    for platform, url_template in SOCIAL_SEARCH_URLS:
        url = url_template.replace('{username}', username)
        result['links'].append({'title': f'Search on {platform}', 'url': url})

    return result


# ══════════════════════════════════════════════════════════════════
#  IP Address Enrichment
# ══════════════════════════════════════════════════════════════════

PRIVATE_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255'),
]


def _ip_to_int(ip: str) -> int:
    parts = ip.split('.')
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])


def _is_private_ip(ip: str) -> bool:
    ip_int = _ip_to_int(ip)
    for start, end in PRIVATE_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


def enrich_ip(ip: str) -> dict:
    result = {
        'type': 'ip_address',
        'value': ip,
        'intel': [],
        'links': [],
        'tags': [],
    }

    # Add geolocation enrichment
    geo = enrich_ip_geo(ip)
    result['intel'].extend(geo['intel'])
    result['tags'].extend(geo['tags'])

    ip = ip.strip()
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ipv4_pattern, ip):
        result['intel'].append({'label': 'Status', 'value': 'Invalid IP address format'})
        return result

    # Validate each octet
    octets = ip.split('.')
    if any(int(o) > 255 for o in octets):
        result['intel'].append({'label': 'Status', 'value': 'Invalid IP (octet > 255)'})
        return result

    # Public / Private
    if _is_private_ip(ip):
        result['intel'].append({'label': 'Type', 'value': ' Private IP (LAN)'})
        result['tags'].append('private')
    else:
        result['intel'].append({'label': 'Type', 'value': ' Public IP'})
        result['tags'].append('public')

    # Check first octet for class
    first = int(octets[0])
    if 1 <= first <= 126:
        result['intel'].append({'label': 'Class', 'value': 'Class A'})
    elif 128 <= first <= 191:
        result['intel'].append({'label': 'Class', 'value': 'Class B'})
    elif 192 <= first <= 223:
        result['intel'].append({'label': 'Class', 'value': 'Class C'})

    # Try reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)
        result['intel'].append({'label': 'Reverse DNS', 'value': hostname[0]})
    except socket.herror:
        result['intel'].append({'label': 'Reverse DNS', 'value': 'No PTR record'})

    # OSINT lookup links
    result['links'].append({'title': 'Check on VirusTotal', 'url': f'https://www.virustotal.com/gui/ip-address/{ip}'})
    result['links'].append({'title': 'Check on Shodan', 'url': f'https://www.shodan.io/host/{ip}'})
    result['links'].append({'title': 'Check on AbuseIPDB', 'url': f'https://www.abuseipdb.com/check/{ip}'})
    result['links'].append({'title': 'Check on IPinfo.io', 'url': f'https://ipinfo.io/{ip}'})
    result['links'].append({'title': 'Check on Censys', 'url': f'https://search.censys.io/search?resource=hosts&q={ip}'})

    return result


# ══════════════════════════════════════════════════════════════════
#  Cryptocurrency Enrichment
# ══════════════════════════════════════════════════════════════════

CRYPTO_PATTERNS = {
    'bitcoin': (r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', 'Bitcoin (BTC)'),
    'ethereum': (r'^0x[a-fA-F0-9]{40}$', 'Ethereum (ETH)'),
    'litecoin': (r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$', 'Litecoin (LTC)'),
    'monero': (r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', 'Monero (XMR)'),
    'ripple': (r'^r[1-9A-HJ-NP-Za-km-z]{25,34}$', 'Ripple (XRP)'),
    'dogecoin': (r'^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$', 'Dogecoin (DOGE)'),
    'tron': (r'^T[1-9A-HJ-NP-Za-km-z]{33}$', 'TRON (TRX)'),
    'cardano': (r'^addr1[0-9a-z]{58}$', 'Cardano (ADA)'),
    'solana': (r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', 'Solana (SOL)'),
}


def enrich_crypto(address: str) -> dict:
    result = {
        'type': 'cryptocurrency',
        'value': address,
        'intel': [],
        'links': [],
        'tags': [],
    }

    address = address.strip()
    result['intel'].append({'label': 'Address', 'value': address[:20] + '...' if len(address) > 20 else address})

    found = False
    for name, (pattern, label) in CRYPTO_PATTERNS.items():
        if re.match(pattern, address):
            result['intel'].append({'label': 'Type', 'value': label})
            result['tags'].append(name)
            found = True

            # Blockchain explorer links
            if name == 'bitcoin':
                result['links'].append({'title': 'Check on Blockchain.com', 'url': f'https://www.blockchain.com/explorer/addresses/btc/{address}'})
                result['links'].append({'title': 'Check on Blockchair', 'url': f'https://blockchair.com/bitcoin/address/{address}'})
            elif name == 'ethereum':
                result['links'].append({'title': 'Check on Etherscan', 'url': f'https://etherscan.io/address/{address}'})
                result['links'].append({'title': 'Check on Blockchair', 'url': f'https://blockchair.com/ethereum/address/{address}'})
            elif name == 'litecoin':
                result['links'].append({'title': 'Check on Blockchair', 'url': f'https://blockchair.com/litecoin/address/{address}'})
            elif name == 'monero':
                result['links'].append({'title': 'Check on XMRChain', 'url': f'https://xmrchain.net/search?value={address}'})
            elif name == 'ripple':
                result['links'].append({'title': 'Check on XRPScan', 'url': f'https://xrpscan.com/account/{address}'})
            elif name == 'dogecoin':
                result['links'].append({'title': 'Check on Blockchair', 'url': f'https://blockchair.com/dogecoin/address/{address}'})
            elif name == 'tron':
                result['links'].append({'title': 'Check on Tronscan', 'url': f'https://tronscan.org/#/address/{address}'})
            elif name == 'solana':
                result['links'].append({'title': 'Check on Solscan', 'url': f'https://solscan.io/account/{address}'})

            result['links'].append({'title': 'Search on Google', 'url': f'https://www.google.com/search?q={address}'})
            break

    if not found:
        # Try length-based guess
        length = len(address)
        if length == 34:
            result['intel'].append({'label': 'Guess', 'value': ' May be a Bitcoin address (34 chars)'})
        elif length == 42:
            result['intel'].append({'label': 'Guess', 'value': ' May be an Ethereum address (42 chars with 0x)'})
        else:
            result['intel'].append({'label': 'Status', 'value': 'Unknown cryptocurrency format'})

    return result


# ══════════════════════════════════════════════════════════════════
#  IP Geolocation Enrichment
# ══════════════════════════════════════════════════════════════════

def enrich_ip_geo(ip: str) -> dict:
    """Get geolocation data for a public IP using ip-api.com (free, no key)."""
    result = {
        'intel': [],
        'tags': [],
    }
    try:
        resp = _http_get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,proxy,hosting', timeout=4)
        if resp:
            data = json.loads(resp)
            if data.get('status') == 'success':
                result['intel'].append({'label': 'Country', 'value': f'{data.get("country", "?")} ({data.get("countryCode", "?")})'})
                result['intel'].append({'label': 'City', 'value': f'{data.get("city", "?")}, {data.get("regionName", "?")}'})
                if data.get('zip'):
                    result['intel'].append({'label': 'ZIP', 'value': data['zip']})
                if data.get('lat') and data.get('lon'):
                    result['intel'].append({'label': 'Coordinates', 'value': f'{data["lat"]}, {data["lon"]}'})
                    result['links'].append({'title': 'Open in Google Maps', 'url': f'https://www.google.com/maps?q={data["lat"]},{data["lon"]}'})
                result['intel'].append({'label': 'ISP', 'value': data.get('isp', 'Unknown')})
                result['intel'].append({'label': 'Organization', 'value': data.get('org', 'Unknown')})
                if data.get('as'):
                    result['intel'].append({'label': 'AS Number', 'value': data['as']})
                if data.get('proxy'):
                    result['intel'].append({'label': 'Proxy/VPN', 'value': ' Proxy or VPN detected'})
                    result['tags'].append('proxy')
                if data.get('hosting'):
                    result['intel'].append({'label': 'Hosting', 'value': ' Hosting provider'})
                    result['tags'].append('hosting')
            else:
                result['intel'].append({'label': 'Geo Status', 'value': 'Could not locate IP'})
        else:
            result['intel'].append({'label': 'Geo Status', 'value': 'Geo lookup unavailable'})
    except Exception:
        result['intel'].append({'label': 'Geo Status', 'value': 'Geo lookup failed'})

    return result


# ══════════════════════════════════════════════════════════════════
#  Main Enrichment Router
# ══════════════════════════════════════════════════════════════════

def enrich_entity(entity_type: str, name: str, profile_url: str = '') -> dict:
    """Route to the correct enrichment function based on entity type."""
    enrichment_map = {
        'phone_number': enrich_phone,
        'email': enrich_email,
        'domain': enrich_domain,
        'url': enrich_domain,
        'username': enrich_username,
        'ip_address': enrich_ip,
    }

    # For social_media: enrich the profile URL as a domain/URL, or treat name as username
    if entity_type == 'social_media':
        if profile_url:
            return enrich_domain(profile_url)
        else:
            return enrich_username(name)

    if entity_type == 'cryptocurrency':
        return enrich_crypto(name)

    handler = enrichment_map.get(entity_type)
    if handler:
        return handler(name)

    # For types without specific enrichment, return generic info
    return {
        'type': entity_type,
        'value': name,
        'intel': [{'label': 'Status', 'value': f'No specific enrichment available for "{entity_type}"'}],
        'links': [],
        'tags': [],
    }
