# Enhanced Django RAG Chatbot with Additional Features
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

import os
import numpy as np
from getpass import getpass
import asyncio
import json
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import re
from dataclasses import dataclass
from groq import Groq
import nest_asyncio
from sentence_transformers import SentenceTransformer
import sqlite3
from urllib.parse import quote

# Patch asyncio for Colab
nest_asyncio.apply()

@dataclass
class ThreatIntelligence:
    cve_id: str
    severity: str
    description: str
    cvss_score: float
    exploit_available: bool
    remediation: str
    attack_vector: str = ""

@dataclass
class ExploitInfo:
    exploit_id: str
    title: str
    description: str
    platform: str
    verified: bool
    code_available: bool

@dataclass
class MitreAttackInfo:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    platforms: List[str]
    detection: str
    mitigation: str

@dataclass
class ThreatIndicator:
    ioc_type: str
    value: str
    threat_type: str
    confidence: int
    source: str

class DjangoRAGChatbot:
    def __init__(self, db_path="cybersec_knowledge.db"):
        try:
            print("📥 Loading SentenceTransformer model...")
            self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
            print("✅ SentenceTransformer loaded successfully")
        except Exception as e:
            print(f"⚠️ Warning: Could not load SentenceTransformer: {e}")
            print("🔄 Using basic text matching instead")
            self.embedder = None

        self.docs = []
        self.embeddings = None
        self.db_path = db_path
        self.init_database()

        # Pattern matching
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }

        # API Configuration
        self.nvd_api_key = os.environ.get("NVD_API_KEY")
        self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.alienvault_api_key = os.environ.get("ALIENVAULT_API_KEY")

    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                cve_id TEXT PRIMARY KEY,
                severity TEXT,
                description TEXT,
                cvss_score REAL,
                exploit_available INTEGER,
                remediation TEXT,
                attack_vector TEXT,
                last_updated TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploit_db (
                exploit_id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                platform TEXT,
                verified INTEGER,
                code_available INTEGER,
                last_updated TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mitre_attack (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT,
                tactic TEXT,
                description TEXT,
                platforms TEXT,
                detection TEXT,
                mitigation TEXT,
                last_updated TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT,
                value TEXT,
                threat_type TEXT,
                confidence INTEGER,
                source TEXT,
                last_updated TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT,
                title TEXT,
                content TEXT,
                tags TEXT,
                last_updated TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def add_documents(self, docs):
        """Add documents to knowledge base"""
        if self.embedder is None:
            # Store documents without embeddings
            self.docs = docs.copy() if hasattr(docs, 'copy') else list(docs)
            print(f"📚 Added {len(self.docs)} documents (text-only mode)")
            
            # Still store in database even without embeddings
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for doc in docs:
                cursor.execute('''
                    INSERT OR REPLACE INTO knowledge_base
                    (category, title, content, tags, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    doc.get('category', 'general'),
                    doc.get('title', ''),
                    doc['text'],
                    doc.get('tags', ''),
                    datetime.now().isoformat()
                ))

            conn.commit()
            conn.close()
            return
    
        texts = [d["text"] for d in docs]
        try:
            embs = self.embedder.encode(texts, convert_to_numpy=True)
            
            if self.embeddings is None:
                self.embeddings = embs
                self.docs = docs.copy()
            else:
                self.embeddings = np.vstack([self.embeddings, embs])
                self.docs.extend(docs)
                
            print(f"📚 Added {len(docs)} documents with embeddings")
        except Exception as e:
            print(f"⚠️ Warning: Could not create embeddings: {e}")
            self.docs = docs.copy() if hasattr(docs, 'copy') else list(docs)

        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for doc in docs:
            cursor.execute('''
                INSERT OR REPLACE INTO knowledge_base
                (category, title, content, tags, last_updated)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                doc.get('category', 'general'),
                doc.get('title', ''),
                doc['text'],
                doc.get('tags', ''),
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()


    async def fetch_cve_data(self, cve_id: str) -> Optional[ThreatIntelligence]:
        """Fetch CVE data from NVD"""
        try:
            # Check cache first
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM threat_intel WHERE cve_id = ? AND last_updated > ?",
                (cve_id, (datetime.now() - timedelta(days=1)).isoformat())
            )
            cached = cursor.fetchone()

            if cached:
                conn.close()
                return ThreatIntelligence(
                    cve_id=cached[0],
                    severity=cached[1],
                    description=cached[2],
                    cvss_score=cached[3],
                    exploit_available=bool(cached[4]),
                    remediation=cached[5],
                    attack_vector=cached[6] or ""
                )

            conn.close()

            # Fetch from NVD API
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

            def sync_request():
                response = requests.get(url, headers=headers, timeout=15)
                return response.json() if response.status_code == 200 else None

            data = await asyncio.to_thread(sync_request)

            if data and data.get('vulnerabilities'):
                vuln = data['vulnerabilities'][0]['cve']

                cvss_score = 0.0
                attack_vector = "UNKNOWN"
                if 'metrics' in vuln:
                    for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if metric_type in vuln['metrics'] and vuln['metrics'][metric_type]:
                            metric = vuln['metrics'][metric_type][0]['cvssData']
                            cvss_score = metric['baseScore']
                            attack_vector = metric.get('attackVector', 'UNKNOWN')
                            break

                severity = "LOW"
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"

                remediation_steps = []
                if severity in ["CRITICAL", "HIGH"]:
                    remediation_steps = [
                        f"Apply security patches for {cve_id} immediately",
                        "Isolate affected systems if possible",
                        "Monitor for exploitation attempts",
                        "Update security configurations"
                    ]
                else:
                    remediation_steps = [
                        f"Schedule patching for {cve_id}",
                        "Review security configurations",
                        "Monitor vendor advisories"
                    ]

                threat_intel = ThreatIntelligence(
                    cve_id=cve_id,
                    severity=severity,
                    description=vuln['descriptions'][0]['value'] if vuln.get('descriptions') else "",
                    cvss_score=cvss_score,
                    exploit_available=cvss_score >= 7.0,
                    remediation=" | ".join(remediation_steps),
                    attack_vector=attack_vector
                )

                # Cache result
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intel VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat_intel.cve_id,
                    threat_intel.severity,
                    threat_intel.description,
                    threat_intel.cvss_score,
                    int(threat_intel.exploit_available),
                    threat_intel.remediation,
                    threat_intel.attack_vector,
                    datetime.now().isoformat()
                ))
                conn.commit()
                conn.close()

                return threat_intel

        except Exception as e:
            print(f"Error fetching CVE data: {e}")

        return None

    async def analyze_ioc_virustotal(self, ioc: str) -> Optional[ThreatIndicator]:
        """Analyze IOC with VirusTotal"""
        try:
            if not self.virustotal_api_key:
                return None

            headers = {"x-apikey": self.virustotal_api_key}

            # Determine IOC type and endpoint
            if self.ip_pattern.match(ioc):
                endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
                ioc_type = "IP"
            elif self.domain_pattern.match(ioc):
                endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"
                ioc_type = "Domain"
            elif any(pattern.match(ioc) for pattern in self.hash_patterns.values()):
                endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
                ioc_type = "Hash"
            else:
                return None

            def sync_vt_request():
                response = requests.get(endpoint, headers=headers, timeout=10)
                return response.json() if response.status_code == 200 else None

            data = await asyncio.to_thread(sync_vt_request)

            if data and 'data' in data:
                attributes = data['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                total_count = sum(stats.values()) if stats else 1

                threat_type = "Clean"
                if malicious_count > 5:
                    threat_type = "Malicious"
                elif malicious_count > 0:
                    threat_type = "Suspicious"

                return ThreatIndicator(
                    ioc_type=ioc_type,
                    value=ioc,
                    threat_type=threat_type,
                    confidence=int((malicious_count / total_count) * 100) if total_count > 0 else 0,
                    source="VirusTotal"
                )

        except Exception as e:
            print(f"Error analyzing IOC: {e}")

        return None

    async def fetch_mitre_techniques(self, query: str) -> List[MitreAttackInfo]:
        """Fetch MITRE techniques"""
        try:
            # Check cache
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM mitre_attack WHERE technique_name LIKE ? OR description LIKE ?",
                (f"%{query}%", f"%{query}%")
            )
            cached_results = cursor.fetchall()

            if cached_results:
                conn.close()
                return [MitreAttackInfo(
                    technique_id=row[0],
                    technique_name=row[1],
                    tactic=row[2],
                    description=row[3][:150],
                    platforms=json.loads(row[4]) if row[4] else [],
                    detection=row[5],
                    mitigation=row[6]
                ) for row in cached_results[:3]]

            conn.close()

            # Enhanced MITRE data
            mitre_data = {
                "phishing": MitreAttackInfo(
                    technique_id='T1566',
                    technique_name='Phishing',
                    tactic='Initial Access',
                    description='Adversaries may send spearphishing emails with malicious attachments or links to gain access to victim systems',
                    platforms=["Windows", "macOS", "Linux"],
                    detection='Monitor email gateways for suspicious attachments, analyze email headers, implement DMARC/SPF',
                    mitigation='Security awareness training, email filtering, endpoint protection, disable macros'
                ),
                "privilege escalation": MitreAttackInfo(
                    technique_id='T1068',
                    technique_name='Exploitation for Privilege Escalation',
                    tactic='Privilege Escalation',
                    description='Adversaries may exploit software vulnerabilities in an attempt to escalate privileges',
                    platforms=["Windows", "Linux", "macOS"],
                    detection='Monitor for unusual process execution, privilege changes, system calls',
                    mitigation='Keep systems patched, implement least privilege, use application sandboxing'
                ),
                "lateral movement": MitreAttackInfo(
                    technique_id='T1021',
                    technique_name='Remote Services',
                    tactic='Lateral Movement',
                    description='Adversaries may use valid accounts to log into remote services to move laterally',
                    platforms=["Windows", "Linux"],
                    detection='Monitor authentication logs, network connections, unusual service usage',
                    mitigation='Network segmentation, strong authentication, monitor privileged accounts'
                ),
                "persistence": MitreAttackInfo(
                    technique_id='T1543',
                    technique_name='Create or Modify System Process',
                    tactic='Persistence',
                    description='Adversaries may create or modify system processes to repeatedly execute malicious payloads',
                    platforms=["Windows", "Linux", "macOS"],
                    detection='Monitor service creation/modification, startup programs, system process changes',
                    mitigation='Restrict service creation permissions, monitor system processes'
                ),
                "defense evasion": MitreAttackInfo(
                    technique_id='T1055',
                    technique_name='Process Injection',
                    tactic='Defense Evasion',
                    description='Adversaries may inject code into processes to evade process-based defenses',
                    platforms=["Windows", "macOS", "Linux"],
                    detection='Monitor process behavior, memory analysis, API calls',
                    mitigation='Behavior-based detection, application sandboxing, process isolation'
                )
            }

            results = []
            for keyword, data in mitre_data.items():
                if keyword in query.lower():
                    results.append(data)

            return results

        except Exception:
            return []

    def extract_indicators(self, query: str) -> Dict:
        """Extract all indicators from query"""
        cve_ids = self.cve_pattern.findall(query)
        ips = self.ip_pattern.findall(query)
        domains = [d for d in self.domain_pattern.findall(query)
                  if not any(common in d.lower() for common in ['google.com', 'microsoft.com', 'example.com'])]
        hashes = []
        for pattern in self.hash_patterns.values():
            hashes.extend(pattern.findall(query))

        return {
            'cves': cve_ids,
            'ips': ips,
            'domains': domains,
            'hashes': hashes,
            'all_iocs': ips + domains + hashes
        }

    async def get_response(self, user_input: str) -> str:
        """Generate Django chatbot response"""
        # Extract indicators
        indicators = self.extract_indicators(user_input)

        # Retrieve relevant documents using RAG
        context = ""
        if self.embeddings is not None:
            q_emb = self.embedder.encode([user_input], convert_to_numpy=True)
            sims = (self.embeddings @ q_emb.T).squeeze()
            top_idx = np.argsort(-sims)[:5]
            relevant_docs = [self.docs[i] for i in top_idx if sims[i] > 0.1]
            context = "\n".join([f"- {doc['text']}" for doc in relevant_docs])

        # Collect threat intelligence
        threat_intel_data = []

        # Get CVE data
        for cve_id in indicators['cves'][:3]:  # Limit to avoid too much data
            intel = await self.fetch_cve_data(cve_id.upper())
            if intel:
                threat_intel_data.append(f"CVE {intel.cve_id}: {intel.severity} severity (CVSS: {intel.cvss_score}), Attack Vector: {intel.attack_vector}")

        # Analyze IOCs
        ioc_data = []
        for ioc in indicators['all_iocs'][:3]:  # Limit to avoid rate limits
            ioc_result = await self.analyze_ioc_virustotal(ioc)
            if ioc_result:
                ioc_data.append(f"{ioc_result.ioc_type} {ioc_result.value}: {ioc_result.threat_type} ({ioc_result.confidence}% confidence)")

        # Get MITRE techniques
        mitre_data = []
        mitre_techniques = await self.fetch_mitre_techniques(user_input)
        for technique in mitre_techniques[:2]:  # Limit results
            mitre_data.append(f"MITRE {technique.technique_id} - {technique.technique_name}: {technique.description[:100]}...")

        # Build intelligence summary
        intel_summary = ""
        if threat_intel_data:
            intel_summary += f"\nCVE Intelligence: {'; '.join(threat_intel_data)}"
        if ioc_data:
            intel_summary += f"\nIOC Analysis: {'; '.join(ioc_data)}"
        if mitre_data:
            intel_summary += f"\nMITRE Techniques: {'; '.join(mitre_data)}"

        # Create comprehensive context
        full_context = ""
        if context:
            full_context += f"Cybersecurity Knowledge: {context}\n"
        if intel_summary:
            full_context += f"Threat Intelligence:{intel_summary}\n"

        # Generate response using a more conversational system prompt
        system_prompt = f"""You are Django, a knowledgeable cybersecurity expert and helpful assistant. You can discuss any cybersecurity topic and provide accurate, practical guidance.

Available information:
{full_context if full_context else "General cybersecurity knowledge available."}

Guidelines:
- Be conversational and helpful
- Provide accurate cybersecurity information
- Use the threat intelligence when relevant
- Answer any cybersecurity question, not just specific topics
- Be practical and actionable in your advice
- Explain technical concepts clearly"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]

        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                temperature=0.3,
                max_tokens=800
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"I encountered an error processing your request: {str(e)}"

# Initialize system with API keys
print("Setting up Django RAG Chatbot...")

# Required API key
if not os.environ.get("GROQ_API_KEY"):
    GROQ_API_KEY = getpass("Enter your Groq API key (required): ")
    os.environ["GROQ_API_KEY"] = GROQ_API_KEY

# Optional API keys
if not os.environ.get("VIRUSTOTAL_API_KEY"):
    vt_key = getpass("Enter VirusTotal API key (optional, press Enter to skip): ")
    if vt_key.strip():
        os.environ["VIRUSTOTAL_API_KEY"] = vt_key

if not os.environ.get("ALIENVAULT_API_KEY"):
    otx_key = getpass("Enter AlienVault OTX API key (optional, press Enter to skip): ")
    if otx_key.strip():
        os.environ["ALIENVAULT_API_KEY"] = otx_key

if not os.environ.get("NVD_API_KEY"):
    nvd_key = getpass("Enter NVD API key (optional, press Enter to skip): ")
    if nvd_key.strip():
        os.environ["NVD_API_KEY"] = nvd_key

groq_client = Groq(api_key=os.environ["GROQ_API_KEY"])

# Create Django chatbot
django = DjangoRAGChatbot()

# Comprehensive cybersecurity knowledge base
comprehensive_knowledge = [
    {"category": "authentication", "text": "Multi-Factor Authentication (MFA) should use hardware security keys (FIDO2/WebAuthn), TOTP authenticator apps, or SMS as backup. Avoid SMS-only MFA due to SIM swapping attacks. Implement adaptive authentication based on risk factors like location, device, and behavior patterns. Consider passwordless authentication for enhanced security.", "tags": "mfa,authentication,fido2,webauthn,passwordless"},

    {"category": "network_security", "text": "Zero Trust Network Architecture assumes no implicit trust and continuously validates every transaction. Implement micro-segmentation using software-defined perimeters, enforce least-privilege access, monitor all network traffic with behavioral analysis and anomaly detection. Use VLANs, firewalls, and network access control (NAC) solutions.", "tags": "zero_trust,network,microsegmentation,nac"},

    {"category": "vulnerability_management", "text": "Vulnerability management should prioritize based on CVSS score, exploitability (EPSS), asset criticality, and threat intelligence. Critical vulnerabilities (CVSS 9-10) require patching within 24-72 hours. Use automated scanning tools like Nessus, Qualys, or OpenVAS integrated with patch management systems. Maintain asset inventory and classification.", "tags": "vulnerability,cvss,epss,scanning,patching"},

    {"category": "incident_response", "text": "Incident response follows NIST framework: Preparation, Detection/Analysis, Containment/Eradication/Recovery, and Post-Incident Activity. Maintain updated playbooks, conduct tabletop exercises quarterly, establish clear communication channels, and integrate with SIEM/SOAR platforms for automated response. Document lessons learned.", "tags": "incident_response,nist,playbooks,siem,soar,tabletop"},

    {"category": "threat_hunting", "text": "Proactive threat hunting uses hypothesis-driven investigations based on threat intelligence, IOCs, and behavioral analytics. Hunt for MITRE ATT&CK techniques, analyze process execution patterns, network connections, file system changes, and registry modifications. Use tools like Velociraptor, OSQuery, or PowerShell for data collection.", "tags": "threat_hunting,mitre_attack,iocs,behavioral_analytics,velociraptor"},

    {"category": "endpoint_security", "text": "Modern endpoint protection requires EDR/XDR solutions with behavioral analysis, machine learning detection, and automated response capabilities. Implement application control (whitelisting), disable unnecessary services and ports, use local administrator password solutions (LAPS), and maintain updated endpoint inventory with configuration management.", "tags": "edr,xdr,endpoint_protection,application_control,laps"},

    {"category": "cloud_security", "text": "Cloud security requires understanding the shared responsibility model. Implement proper IAM with least privilege, enable CloudTrail/logging, use Cloud Security Posture Management (CSPM) tools, encrypt data in transit and at rest, and regularly audit configurations. Follow CIS benchmarks for hardening and implement cloud workload protection platforms.", "tags": "cloud_security,iam,cspm,encryption,cis_benchmarks,cwpp"},

    {"category": "data_protection", "text": "Data Loss Prevention (DLP) should classify data by sensitivity, implement encryption for data at rest and in transit using AES-256 and TLS 1.3, establish data retention policies, monitor data access patterns, and maintain secure backup and recovery procedures with regular restore testing. Implement data governance frameworks.", "tags": "dlp,encryption,data_classification,backup,governance"},

    {"category": "compliance", "text": "Security compliance frameworks include NIST Cybersecurity Framework, ISO 27001, SOC 2 Type II, PCI DSS, GDPR, HIPAA, and FedRAMP. Implement continuous compliance monitoring, maintain documentation, conduct regular audits, and use GRC platforms to manage controls and evidence collection. Map controls to multiple frameworks.", "tags": "compliance,nist,iso27001,soc2,pci_dss,gdpr,hipaa,fedramp"},

    {"category": "security_architecture", "text": "Security architecture principles include defense in depth, fail-safe defaults, economy of mechanism, complete mediation, open design, separation of privilege, least privilege, and psychological acceptability. Design secure network topologies, implement security controls at multiple layers, and maintain security design patterns and reference architectures.", "tags": "security_architecture,defense_in_depth,security_principles,design_patterns"},

    {"category": "cryptography", "text": "Use modern cryptographic standards: AES-256 for symmetric encryption, RSA-3072 or ECC P-384 for asymmetric encryption, SHA-256 or SHA-3 for hashing, and PBKDF2/bcrypt/scrypt for password hashing. Implement proper key management with hardware security modules (HSMs), regular key rotation, and secure key storage.", "tags": "cryptography,aes,rsa,ecc,sha,key_management,hsm"},

    {"category": "penetration_testing", "text": "Penetration testing methodology follows phases: reconnaissance, scanning, enumeration, vulnerability assessment, exploitation, post-exploitation, and reporting. Use frameworks like OWASP Testing Guide, NIST SP 800-115, or PTES. Document findings with risk ratings, proof of concepts, and detailed remediation recommendations.", "tags": "penetration_testing,owasp,methodology,vulnerability_assessment,ptes"},

    {"category": "security_monitoring", "text": "Security monitoring requires SIEM/SOAR integration, log aggregation from all sources, correlation rules for threat detection, baseline behavioral analysis, and automated alerting. Monitor for indicators of compromise, lateral movement, privilege escalation, and data exfiltration patterns. Implement security dashboards and metrics.", "tags": "security_monitoring,siem,soar,correlation_rules,ioc,dashboards"},

    {"category": "malware_analysis", "text": "Malware analysis includes static analysis (strings, PE headers, entropy), dynamic analysis (sandbox execution, behavioral monitoring), and reverse engineering. Use tools like IDA Pro, Ghidra, Process Monitor, Wireshark, and isolated analysis environments. Document TTPs and generate IOCs for threat intelligence.", "tags": "malware_analysis,static_analysis,dynamic_analysis,reverse_engineering,sandbox"},

    {"category": "forensics", "text": "Digital forensics follows acquisition, preservation, analysis, and presentation phases. Maintain chain of custody, use write-blocking hardware, create forensic images with tools like FTK Imager or dd, analyze artifacts with Autopsy or EnCase, and document all procedures for legal admissibility. Follow standard forensic procedures.", "tags": "digital_forensics,chain_of_custody,forensic_imaging,artifact_analysis,autopsy"},

    {"category": "risk_management", "text": "Cybersecurity risk management involves identifying, assessing, treating, and monitoring risks. Use frameworks like NIST RMF, ISO 31000, or FAIR for quantitative risk analysis. Implement risk registers, conduct regular risk assessments, define risk appetite and tolerance levels, and establish risk treatment strategies including acceptance, mitigation, transfer, and avoidance.", "tags": "risk_management,nist_rmf,iso31000,fair,risk_assessment"},

    {"category": "security_awareness", "text": "Security awareness programs should include regular training on phishing, social engineering, password security, and incident reporting. Use simulated phishing campaigns, gamification, and role-based training. Measure effectiveness through metrics like click rates, reporting rates, and behavioral changes. Update content based on current threat landscape.", "tags": "security_awareness,training,phishing_simulation,social_engineering"},

    {"category": "application_security", "text": "Application security involves secure coding practices, security testing throughout SDLC, and runtime protection. Implement SAST, DAST, and IAST tools, conduct code reviews, use secure coding standards like OWASP Top 10, and implement application firewalls. Include security requirements in design phase and conduct threat modeling.", "tags": "application_security,sast,dast,iast,owasp_top10,secure_coding,threat_modeling"},

    {"category": "identity_management", "text": "Identity and Access Management (IAM) should implement single sign-on (SSO), privileged access management (PAM), identity governance, and access certification. Use role-based access control (RBAC) or attribute-based access control (ABAC), implement zero trust principles, and maintain identity lifecycle management with automated provisioning and deprovisioning.", "tags": "iam,sso,pam,rbac,abac,identity_governance,zero_trust"},

    {"category": "security_operations", "text": "Security Operations Centers (SOCs) require 24/7 monitoring, incident response capabilities, threat intelligence integration, and continuous improvement processes. Implement tiered analyst structure (L1/L2/L3), define standard operating procedures, maintain runbooks and playbooks, and use metrics like MTTD (Mean Time to Detection) and MTTR (Mean Time to Response).", "tags": "soc,security_operations,incident_response,threat_intelligence,mttd,mttr"}
]

# ... (keep all your existing code above) ...
django.add_documents(comprehensive_knowledge)
print("Django RAG Chatbot initialized with comprehensive cybersecurity knowledge base.")

async def chat():
    print("\nDjango RAG Chatbot is ready. Ask me anything about cybersecurity!")
    
    while True:
        user_input = input("\nYou: ")
        
        if user_input.lower() in ['quit', 'exit', 'bye']:
            print("Django: Goodbye! Stay secure!")
            break
        
        response = await django.get_response(user_input)
        print(f"\nDjango: {response}")

# Only run the chat interface when this file is executed directly
if __name__ == "__main__":
    import asyncio
    asyncio.run(chat())


import asyncio
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
import sqlite3
from datetime import datetime, timedelta
import hashlib

@dataclass
class SecurityAlert:
    alert_id: str
    severity: str
    title: str
    description: str
    timestamp: str
    source: str
    indicators: List[str]

class EnhancedDjangoRAG(DjangoRAGChatbot):
    def __init__(self, db_path="cybersec_knowledge.db"):
        super().__init__(db_path)
        self.conversation_history = []
        self.user_context = {}
        self.init_enhanced_database()

    def init_enhanced_database(self):
        """Initialize additional database tables for enhanced features"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Conversation history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                user_message TEXT,
                bot_response TEXT,
                timestamp TEXT,
                context_data TEXT
            )
        ''')

        # Security alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                alert_id TEXT PRIMARY KEY,
                severity TEXT,
                title TEXT,
                description TEXT,
                timestamp TEXT,
                source TEXT,
                indicators TEXT,
                acknowledged INTEGER DEFAULT 0
            )
        ''')

        # User preferences and context
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_context (
                user_id TEXT PRIMARY KEY,
                role TEXT,
                organization TEXT,
                security_level TEXT,
                preferred_detail_level TEXT,
                last_updated TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now().isoformat()
        return hashlib.md5(timestamp.encode()).hexdigest()[:16]

    def save_conversation(self, session_id: str, user_message: str, bot_response: str, context_data: Dict):
        """Save conversation to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO conversation_history
            (session_id, user_message, bot_response, timestamp, context_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            session_id,
            user_message,
            bot_response,
            datetime.now().isoformat(),
            json.dumps(context_data)
        ))
        conn.commit()
        conn.close()

    def get_conversation_context(self, session_id: str, limit: int = 5) -> List[Dict]:
        """Retrieve recent conversation history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT user_message, bot_response, context_data FROM conversation_history
            WHERE session_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (session_id, limit))

        history = []
        for row in cursor.fetchall():
            history.append({
                'user_message': row[0],
                'bot_response': row[1],
                'context_data': json.loads(row[2]) if row[2] else {}
            })

        conn.close()
        return list(reversed(history))  # Return in chronological order

    async def analyze_attack_chain(self, indicators: Dict) -> Dict:
        """Analyze potential attack chains from indicators"""
        attack_chain = {
            'phases': [],
            'confidence': 0,
            'recommendations': []
        }

        # Simple attack chain analysis based on indicators
        if indicators['cves'] and indicators['all_iocs']:
            attack_chain['phases'].append({
                'phase': 'Initial Access',
                'description': f"Potential exploitation of {', '.join(indicators['cves'][:2])}",
                'indicators': indicators['cves']
            })

            if indicators['ips']:
                attack_chain['phases'].append({
                    'phase': 'Command & Control',
                    'description': f"Communication with suspicious IPs: {', '.join(indicators['ips'][:2])}",
                    'indicators': indicators['ips']
                })

            attack_chain['confidence'] = 75
            attack_chain['recommendations'] = [
                "Isolate affected systems immediately",
                "Block suspicious IP addresses at firewall",
                "Apply patches for identified CVEs",
                "Monitor for lateral movement indicators"
            ]

        return attack_chain

    async def generate_security_report(self, timeframe_days: int = 7) -> Dict:
        """Generate security summary report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get recent threat intelligence
        since_date = (datetime.now() - timedelta(days=timeframe_days)).isoformat()

        cursor.execute('''
            SELECT severity, COUNT(*) FROM threat_intel
            WHERE last_updated > ?
            GROUP BY severity
        ''', (since_date,))
        cve_stats = dict(cursor.fetchall())

        cursor.execute('''
            SELECT threat_type, COUNT(*) FROM threat_indicators
            WHERE last_updated > ?
            GROUP BY threat_type
        ''', (since_date,))
        ioc_stats = dict(cursor.fetchall())

        conn.close()

        report = {
            'timeframe': f"Last {timeframe_days} days",
            'cve_analysis': cve_stats,
            'ioc_analysis': ioc_stats,
            'recommendations': [
                "Continue monitoring for new vulnerabilities",
                "Update threat intelligence feeds",
                "Review and update security controls"
            ]
        }

        return report

    def create_security_alert(self, title: str, description: str, severity: str, indicators: List[str]) -> SecurityAlert:
        """Create and store security alert"""
        alert_id = f"ALERT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        alert = SecurityAlert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now().isoformat(),
            source="Django Chatbot",
            indicators=indicators
        )

        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id,
            alert.severity,
            alert.title,
            alert.description,
            alert.timestamp,
            alert.source,
            json.dumps(alert.indicators),
            0  # not acknowledged
        ))
        conn.commit()
        conn.close()

        return alert

    async def enhanced_get_response(self, user_input: str, session_id: str = None) -> str:
        """Enhanced response generation with conversation context"""

        if not session_id:
            session_id = self.generate_session_id()

        # Get conversation history
        conversation_context = self.get_conversation_context(session_id)

        # Extract indicators and get threat intel (existing functionality)
        indicators = self.extract_indicators(user_input)

        # Enhanced analysis
        attack_chain = await self.analyze_attack_chain(indicators)

        # Check for specific commands
        if user_input.lower().startswith('generate report'):
            report = await self.generate_security_report()
            response = f"Security Report:\n\nCVE Analysis: {report['cve_analysis']}\nIOC Analysis: {report['ioc_analysis']}\n\nRecommendations:\n" + "\n".join(f"• {rec}" for rec in report['recommendations'])

        elif user_input.lower().startswith('create alert'):
            # Parse alert creation request
            alert = self.create_security_alert(
                title="User Generated Alert",
                description=user_input,
                severity="MEDIUM",
                indicators=indicators['all_iocs']
            )
            response = f"Created security alert {alert.alert_id} with {len(alert.indicators)} indicators."

        else:
            # Build enhanced context with conversation history
            conversation_summary = ""
            if conversation_context:
                conversation_summary = "Previous conversation context:\n"
                for conv in conversation_context[-3:]:  # Last 3 exchanges
                    conversation_summary += f"User asked about: {conv['user_message'][:100]}...\n"

            # Get original RAG response
            base_response = await self.get_response(user_input)

            # Enhance with attack chain analysis if relevant
            if attack_chain['confidence'] > 50:
                attack_info = f"\n\nPotential Attack Chain Analysis:\nConfidence: {attack_chain['confidence']}%\nPhases: {len(attack_chain['phases'])}\nRecommendations: {', '.join(attack_chain['recommendations'][:2])}"
                response = base_response + attack_info
            else:
                response = base_response

        # Save conversation
        context_data = {
            'indicators': indicators,
            'attack_chain_confidence': attack_chain.get('confidence', 0)
        }
        self.save_conversation(session_id, user_input, response, context_data)

        return response

# Additional utility functions for the enhanced chatbot

def load_custom_knowledge_base(file_path: str) -> List[Dict]:
    """Load custom knowledge base from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def export_threat_intelligence(django_instance: DjangoRAGChatbot, output_file: str):
    """Export threat intelligence to JSON file"""
    conn = sqlite3.connect(django_instance.db_path)
    cursor = conn.cursor()

    # Export all threat intel data
    cursor.execute("SELECT * FROM threat_intel")
    threat_intel = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM threat_indicators")
    indicators = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]

    conn.close()

    export_data = {
        'export_timestamp': datetime.now().isoformat(),
        'threat_intel': threat_intel,
        'indicators': indicators
    }

    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"Threat intelligence exported to {output_file}")

# Example usage of enhanced features
async def demo_enhanced_features():
    """Demonstrate enhanced Django chatbot features"""

    enhanced_django = EnhancedDjangoRAG()
    session_id = enhanced_django.generate_session_id()

    # Simulate conversation with memory
    queries = [
        "What is CVE-2024-1234 and how serious is it?",
        "How do I defend against the attack you just mentioned?",
        "Generate report for the last 7 days",
        "Create alert for suspicious IP 192.168.1.100"
    ]

    for query in queries:
        response = await enhanced_django.enhanced_get_response(query, session_id)
        print(f"Query: {query}")
        print(f"Response: {response[:200]}...\n")

# Run demo
# await demo_enhanced_features()

