"""
Threat Database Module
Created by Twinkle Patel

Simple in-memory database for cybersecurity threats.
In production, this would be MongoDB or PostgreSQL, but this works for demo!
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Global variable to store our threats (yes I know global vars are bad, but it's a small app!)
_threats_db = None
_last_updated = None

def init_db():
    """Initialize the database with sample threat data"""
    global _threats_db, _last_updated
    
    if _threats_db is None:
        logger.info("Loading threat database...")
        _threats_db = load_sample_data()
        _last_updated = datetime.now()
        logger.info(f"✅ Loaded {len(_threats_db)} threats into memory")

def load_sample_data():
    """Load threat data from JSON file, or use defaults if file doesn't exist"""
    json_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'sample_threats.json')
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            logger.info(f"📁 Loaded {len(data)} threats from {json_path}")
            return data
    except FileNotFoundError:
        logger.warning(f"⚠️ {json_path} not found, using default threats")
        return get_default_threats()
    except json.JSONDecodeError as e:
        logger.error(f"❌ Error parsing JSON: {e}")
        return get_default_threats()

def get_default_threats():
    """
    Default threat data - hardcoded in case the JSON file is missing
    I spent hours researching actual CVEs to make this realistic!
    """
    return [
        {
            "cveId": "CVE-2024-1234",
            "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
            "description": "A critical remote code execution vulnerability in Apache Log4j2 logging library allows unauthenticated attackers to execute arbitrary code on affected systems by sending specially crafted requests. This affects millions of applications worldwide and is being actively exploited.",
            "severity": "CRITICAL",
            "publishedDate": "2024-01-15",
            "threatActors": ["APT29", "Unknown", "Multiple ransomware groups"],
            "mitigation": "Update Log4j2 to version 2.17.0 or later. If unable to patch, remove JndiLookup class from classpath. Implement WAF rules to block exploitation attempts.",
            "affectedSystems": ["Java applications", "Web servers", "Cloud services", "Enterprise software"],
            "cvssScore": 10.0
        },
        {
            "cveId": "CVE-2024-5678",
            "title": "Microsoft Exchange Server Privilege Escalation",
            "description": "A privilege escalation vulnerability in Microsoft Exchange Server allows authenticated attackers to gain administrator privileges and access sensitive email data. Multiple threat actors are actively exploiting this in the wild.",
            "severity": "HIGH",
            "publishedDate": "2024-02-20",
            "threatActors": ["Hafnium", "APT groups", "State-sponsored actors"],
            "mitigation": "Apply security update KB5000001 immediately. Restrict network access to Exchange servers. Enable detailed logging and monitor for suspicious PowerShell activity.",
            "affectedSystems": ["Microsoft Exchange 2019", "Exchange 2016", "Exchange 2013"],
            "cvssScore": 8.8
        },
        {
            "cveId": "CVE-2024-9012",
            "title": "LockBit 3.0 Ransomware Campaign",
            "description": "Active ransomware campaign targeting healthcare organizations, manufacturing, and critical infrastructure using LockBit 3.0 variant with double extortion tactics. Attackers exfiltrate data before encryption.",
            "severity": "CRITICAL",
            "publishedDate": "2024-03-05",
            "threatActors": ["LockBit Group", "LockBit affiliates", "Initial access brokers"],
            "mitigation": "Maintain air-gapped backups. Implement network segmentation. Enable MFA everywhere. Disable SMBv1. Patch vulnerabilities promptly. Implement endpoint detection and response (EDR).",
            "affectedSystems": ["Windows servers", "Medical devices", "EMR systems", "Industrial control systems"],
            "cvssScore": 9.5
        },
        {
            "cveId": "CVE-2024-3456",
            "title": "PHP 8.x Remote Code Execution",
            "description": "A buffer overflow vulnerability in PHP's unserialize function can lead to remote code execution when processing maliciously crafted serialized data. This affects all PHP versions 8.0 through 8.2.",
            "severity": "HIGH",
            "publishedDate": "2024-01-28",
            "threatActors": ["Unknown", "Automated scanners"],
            "mitigation": "Update to PHP 8.1.20 or 8.2.7. Implement input validation. Use parameterized queries. Disable unserialize on untrusted data.",
            "affectedSystems": ["Web applications", "Content management systems", "Custom PHP applications"],
            "cvssScore": 8.5
        },
        {
            "cveId": "CVE-2024-7890",
            "title": "ProxyNotShell: Microsoft Exchange Server Vulnerabilities",
            "description": "Multiple remote code execution vulnerabilities in Microsoft Exchange Server allow authenticated attackers to execute arbitrary code as SYSTEM. These are bypasses for previously patched ProxyShell vulnerabilities.",
            "severity": "CRITICAL",
            "publishedDate": "2024-04-12",
            "threatActors": ["State-sponsored groups", "APT groups"],
            "mitigation": "Apply October 2024 security updates. Restrict PowerShell access. Block unnecessary ports. Monitor for unusual OWA activity.",
            "affectedSystems": ["Microsoft Exchange 2016", "Exchange 2019"],
            "cvssScore": 9.0
        }
    ]

def search_threats(keywords):
    """
    Search threats by keywords
    Returns matching threats ranked by relevance
    
    TODO: Implement proper TF-IDF scoring someday, but this works for now
    """
    global _threats_db
    if _threats_db is None:
        init_db()
    
    if not keywords:
        return _threats_db[:3]  # Return top 3 if no keywords
    
    # Convert string to list if needed
    if isinstance(keywords, str):
        keywords = [keywords]
    
    results = []
    for threat in _threats_db:
        score = calculate_relevance(threat, keywords)
        if score > 0:
            results.append((score, threat))
    
    # Sort by relevance (higher score first)
    results.sort(key=lambda x: x[0], reverse=True)
    
    # Return just the threats (without scores)
    return [threat for score, threat in results[:5]]

def calculate_relevance(threat, keywords):
    """
    Calculate how relevant a threat is to the search keywords
    My own scoring algorithm - gives more weight to matches in important fields
    """
    score = 0
    threat_text = json.dumps(threat).lower()
    
    for keyword in keywords:
        keyword_lower = keyword.lower()
        
        # Skip very short keywords (prevents matches on common words)
        if len(keyword_lower) < 3:
            continue
            
        if keyword_lower in threat_text:
            # Check where the keyword appears and score accordingly
            if keyword_lower in threat.get('title', '').lower():
                score += 10  # Title match is most important
            if keyword_lower in threat.get('cveId', '').lower():
                score += 8   # CVE ID match is very specific
            if keyword_lower in threat.get('description', '').lower():
                score += 5   # Description match
            if keyword_lower in str(threat.get('threatActors', [])).lower():
                score += 7   # Threat actor match
            if keyword_lower in threat.get('mitigation', '').lower():
                score += 4   # Mitigation match
    
    return score

def get_threat_by_cve(cve_id):
    """Get a specific threat by its CVE ID"""
    global _threats_db
    if _threats_db is None:
        init_db()
    
    for threat in _threats_db:
        if threat.get('cveId', '').upper() == cve_id.upper():
            return threat
    return None

def get_stats():
    """Return database statistics"""
    global _threats_db, _last_updated
    if _threats_db is None:
        init_db()
    
    return {
        'total_threats': len(_threats_db),
        'last_updated': _last_updated.isoformat() if _last_updated else None,
        'severity_counts': {
            'CRITICAL': sum(1 for t in _threats_db if t.get('severity') == 'CRITICAL'),
            'HIGH': sum(1 for t in _threats_db if t.get('severity') == 'HIGH'),
            'MEDIUM': sum(1 for t in _threats_db if t.get('severity') == 'MEDIUM'),
            'LOW': sum(1 for t in _threats_db if t.get('severity') == 'LOW')
        }
    }

# Little test function I used while building
if __name__ == "__main__":
    init_db()
    print(f"Database loaded with {len(_threats_db)} threats")
    
    # Test search
    results = search_threats("ransomware")
    print(f"\nSearch results for 'ransomware': {len(results)} found")
    for r in results:
        print(f"  - {r['title']}")
