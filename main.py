import re
import json
import sqlite3
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import spacy
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import torch
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains.summarize import load_summarize_chain
from langchain.llms import OpenAI
from langchain.docstore.document import Document
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import Counter
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Data structures
@dataclass
class IOC:
    type: str
    value: str
    confidence: float
    source: str
    timestamp: datetime
    context: str

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    cvss_score: Optional[float]
    affected_systems: List[str]
    source: str
    timestamp: datetime

@dataclass
class AttackPattern:
    technique_id: str
    technique_name: str
    description: str
    tactics: List[str]
    mitre_id: str
    source: str
    timestamp: datetime

class ThreatIntelligenceExtractor:
    def __init__(self):
        self.setup_nlp_models()
        self.setup_database()
        self.setup_patterns()
        
    def setup_nlp_models(self):
        """Initialize NLP models and tokenizers"""
        try:
            # Load spaCy model
            self.nlp = spacy.load("en_core_web_sm")
            
            # Load BERT model for NER
            self.tokenizer = AutoTokenizer.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
            self.model = AutoModelForTokenClassification.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
            self.ner_pipeline = pipeline("ner", model=self.model, tokenizer=self.tokenizer, aggregation_strategy="simple")
            
            # Text splitter for long documents
            self.text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=200,
                length_function=len
            )
            
        except Exception as e:
            print(f"Error setting up NLP models: {e}")
            print("Please install required packages: pip install spacy transformers torch")
            
    def setup_database(self):
        """Initialize SQLite database for storing threat intelligence"""
        self.conn = sqlite3.connect('database.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL,
                source TEXT,
                timestamp DATETIME,
                context TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_systems TEXT,
                source TEXT,
                timestamp DATETIME
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                technique_name TEXT,
                description TEXT,
                tactics TEXT,
                mitre_id TEXT,
                source TEXT,
                timestamp DATETIME
            )
        ''')
        
        self.conn.commit()
        
    def setup_patterns(self):
        """Setup regex patterns for IOC extraction"""
        self.ioc_patterns = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'cve': r'CVE-\d{4}-\d{4,7}',
            'file_path': r'[A-Za-z]:\\[^<>:"|?*\n\r]*|/[^<>:"|?*\n\r]*'
        }
        
        self.vulnerability_keywords = [
            'vulnerability', 'exploit', 'buffer overflow', 'sql injection',
            'xss', 'csrf', 'privilege escalation', 'remote code execution',
            'denial of service', 'information disclosure'
        ]
        
        self.attack_pattern_keywords = [
            'lateral movement', 'persistence', 'privilege escalation',
            'defense evasion', 'credential access', 'discovery',
            'collection', 'exfiltration', 'command and control'
        ]

class ThreatDataCollector:
    def __init__(self):
        self.sources = {
            'mitre': 'https://attack.mitre.org/techniques/',
            'cisa': 'https://www.cisa.gov/cybersecurity-advisories',
            'nist': 'https://nvd.nist.gov/vuln/data-feeds'
        }
        
    def collect_mitre_data(self) -> List[Dict]:
        """Collect MITRE ATT&CK data"""
        try:
            # This would typically use MITRE's STIX/TAXII API
            # For demo purposes, we'll use sample data
            sample_techniques = [
                {
                    'technique_id': 'T1078',
                    'technique_name': 'Valid Accounts',
                    'description': 'Adversaries may obtain and abuse credentials of existing accounts',
                    'tactics': ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'],
                    'mitre_id': 'T1078'
                },
                {
                    'technique_id': 'T1059',
                    'technique_name': 'Command and Scripting Interpreter',
                    'description': 'Adversaries may abuse command and script interpreters',
                    'tactics': ['Execution'],
                    'mitre_id': 'T1059'
                }
            ]
            return sample_techniques
        except Exception as e:
            print(f"Error collecting MITRE data: {e}")
            return []
    
    def collect_cve_data(self) -> List[Dict]:
        """Collect CVE data from NVD"""
        try:
            # Sample CVE data for demonstration
            sample_cves = [
                {
                    'cve_id': 'CVE-2024-1234',
                    'description': 'Buffer overflow in XYZ software allows remote code execution',
                    'severity': 'HIGH',
                    'cvss_score': 8.5,
                    'affected_systems': ['Windows', 'Linux']
                },
                {
                    'cve_id': 'CVE-2024-5678',
                    'description': 'SQL injection vulnerability in web application',
                    'severity': 'MEDIUM',
                    'cvss_score': 6.2,
                    'affected_systems': ['Web Applications']
                }
            ]
            return sample_cves
        except Exception as e:
            print(f"Error collecting CVE data: {e}")
            return []

class ThreatIntelligenceProcessor:
    def __init__(self, extractor: ThreatIntelligenceExtractor):
        self.extractor = extractor
        
    def process_text(self, text: str, source: str) -> Dict[str, List]:
        """Process text and extract threat intelligence"""
        results = {
            'iocs': [],
            'vulnerabilities': [],
            'attack_patterns': []
        }
        
        # Extract IOCs
        iocs = self.extract_iocs(text, source)
        results['iocs'] = iocs
        
        # Extract vulnerabilities
        vulnerabilities = self.extract_vulnerabilities(text, source)
        results['vulnerabilities'] = vulnerabilities
        
        # Extract attack patterns
        attack_patterns = self.extract_attack_patterns(text, source)
        results['attack_patterns'] = attack_patterns
        
        return results
    
    def extract_iocs(self, text: str, source: str) -> List[IOC]:
        """Extract Indicators of Compromise from text"""
        iocs = []
        
        for ioc_type, pattern in self.extractor.ioc_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                value = match.group()
                
                # Calculate confidence based on context
                confidence = self.calculate_ioc_confidence(value, text, ioc_type)
                
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                ioc = IOC(
                    type=ioc_type,
                    value=value,
                    confidence=confidence,
                    source=source,
                    timestamp=datetime.now(),
                    context=context
                )
                iocs.append(ioc)
        
        return iocs
    
    def extract_vulnerabilities(self, text: str, source: str) -> List[Vulnerability]:
        """Extract vulnerability information from text"""
        vulnerabilities = []
        
        # Look for CVE mentions
        cve_matches = re.finditer(self.extractor.ioc_patterns['cve'], text, re.IGNORECASE)
        
        for match in cve_matches:
            cve_id = match.group()
            
            # Extract surrounding context for description
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 200)
            context = text[start:end]
            
            # Extract severity if mentioned
            severity = self.extract_severity(context)
            cvss_score = self.extract_cvss_score(context)
            
            vulnerability = Vulnerability(
                cve_id=cve_id,
                description=context,
                severity=severity,
                cvss_score=cvss_score,
                affected_systems=self.extract_affected_systems(context),
                source=source,
                timestamp=datetime.now()
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def extract_attack_patterns(self, text: str, source: str) -> List[AttackPattern]:
        """Extract attack patterns and techniques from text"""
        attack_patterns = []
        
        # Use NER to identify potential attack patterns
        entities = self.extractor.ner_pipeline(text)
        
        for entity in entities:
            if entity['entity_group'] in ['MISC', 'ORG']:
                # Check if entity relates to attack patterns
                if any(keyword in entity['word'].lower() for keyword in self.extractor.attack_pattern_keywords):
                    
                    # Extract MITRE technique ID if present
                    technique_match = re.search(r'T\d{4}', text)
                    technique_id = technique_match.group() if technique_match else 'Unknown'
                    
                    attack_pattern = AttackPattern(
                        technique_id=technique_id,
                        technique_name=entity['word'],
                        description=f"Detected attack pattern: {entity['word']}",
                        tactics=self.extract_tactics(text),
                        mitre_id=technique_id,
                        source=source,
                        timestamp=datetime.now()
                    )
                    attack_patterns.append(attack_pattern)
        
        return attack_patterns
    
    def calculate_ioc_confidence(self, value: str, text: str, ioc_type: str) -> float:
        """Calculate confidence score for IOC based on context"""
        confidence = 0.5  # Base confidence
        
        # Context-based confidence adjustments
        threat_keywords = ['malware', 'malicious', 'threat', 'attack', 'compromise']
        context_window = 100
        
        # Find IOC position in text
        pos = text.lower().find(value.lower())
        if pos != -1:
            start = max(0, pos - context_window)
            end = min(len(text), pos + len(value) + context_window)
            context = text[start:end].lower()
            
            # Increase confidence if threat keywords are nearby
            for keyword in threat_keywords:
                if keyword in context:
                    confidence += 0.1
        
        # IOC type specific adjustments
        if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            confidence += 0.2  # Hashes are typically more reliable
        
        return min(confidence, 1.0)
    
    def extract_severity(self, text: str) -> str:
        """Extract severity level from text"""
        severity_patterns = {
            'CRITICAL': r'\b(?:critical|severe)\b',
            'HIGH': r'\b(?:high|important)\b',
            'MEDIUM': r'\b(?:medium|moderate)\b',
            'LOW': r'\b(?:low|minor)\b'
        }
        
        for severity, pattern in severity_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return severity
        
        return 'UNKNOWN'
    
    def extract_cvss_score(self, text: str) -> Optional[float]:
        """Extract CVSS score from text"""
        cvss_match = re.search(r'cvss[:\s]*(\d+\.?\d*)', text, re.IGNORECASE)
        if cvss_match:
            try:
                return float(cvss_match.group(1))
            except ValueError:
                pass
        return None
    
    def extract_affected_systems(self, text: str) -> List[str]:
        """Extract affected systems from text"""
        systems = []
        system_keywords = ['windows', 'linux', 'macos', 'android', 'ios', 'web', 'server']
        
        for system in system_keywords:
            if system in text.lower():
                systems.append(system.title())
        
        return systems
    
    def extract_tactics(self, text: str) -> List[str]:
        """Extract MITRE tactics from text"""
        tactics = []
        mitre_tactics = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Command and Control'
        ]
        
        for tactic in mitre_tactics:
            if tactic.lower() in text.lower():
                tactics.append(tactic)
        
        return tactics

class ThreatDatabase:
    def __init__(self, extractor: ThreatIntelligenceExtractor):
        self.extractor = extractor
        
    def store_ioc(self, ioc: IOC):
        """Store IOC in database"""
        self.extractor.cursor.execute('''
            INSERT INTO iocs (type, value, confidence, source, timestamp, context)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ioc.type, ioc.value, ioc.confidence, ioc.source, ioc.timestamp, ioc.context))
        self.extractor.conn.commit()
    
    def store_vulnerability(self, vuln: Vulnerability):
        """Store vulnerability in database"""
        affected_systems_str = ','.join(vuln.affected_systems)
        self.extractor.cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, description, severity, cvss_score, affected_systems, source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (vuln.cve_id, vuln.description, vuln.severity, vuln.cvss_score, 
              affected_systems_str, vuln.source, vuln.timestamp))
        self.extractor.conn.commit()
    
    def store_attack_pattern(self, pattern: AttackPattern):
        """Store attack pattern in database"""
        tactics_str = ','.join(pattern.tactics)
        self.extractor.cursor.execute('''
            INSERT INTO attack_patterns 
            (technique_id, technique_name, description, tactics, mitre_id, source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (pattern.technique_id, pattern.technique_name, pattern.description,
              tactics_str, pattern.mitre_id, pattern.source, pattern.timestamp))
        self.extractor.conn.commit()
    
    def get_iocs(self, limit: int = 100) -> List[Dict]:
        """Retrieve IOCs from database"""
        self.extractor.cursor.execute('''
            SELECT * FROM iocs ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in self.extractor.cursor.description]
        return [dict(zip(columns, row)) for row in self.extractor.cursor.fetchall()]
    
    def get_vulnerabilities(self, limit: int = 100) -> List[Dict]:
        """Retrieve vulnerabilities from database"""
        self.extractor.cursor.execute('''
            SELECT * FROM vulnerabilities ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in self.extractor.cursor.description]
        return [dict(zip(columns, row)) for row in self.extractor.cursor.fetchall()]
    
    def get_attack_patterns(self, limit: int = 100) -> List[Dict]:
        """Retrieve attack patterns from database"""
        self.extractor.cursor.execute('''
            SELECT * FROM attack_patterns ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in self.extractor.cursor.description]
        return [dict(zip(columns, row)) for row in self.extractor.cursor.fetchall()]

class ThreatVisualization:
    def __init__(self, database: ThreatDatabase):
        self.database = database
        
    def create_ioc_distribution_chart(self):
        """Create IOC type distribution chart"""
        iocs = self.database.get_iocs()
        
        if not iocs:
            return None
        
        ioc_types = [ioc['type'] for ioc in iocs]
        type_counts = Counter(ioc_types)
        
        fig = px.pie(
            values=list(type_counts.values()),
            names=list(type_counts.keys()),
            title='IOC Type Distribution'
        )
        
        return fig
    
    def create_vulnerability_severity_chart(self):
        """Create vulnerability severity distribution chart"""
        vulns = self.database.get_vulnerabilities()
        
        if not vulns:
            return None
        
        severities = [vuln['severity'] for vuln in vulns]
        severity_counts = Counter(severities)
        
        fig = px.bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            title='Vulnerability Severity Distribution'
        )
        
        return fig
    
    def create_attack_pattern_timeline(self):
        """Create attack pattern timeline"""
        patterns = self.database.get_attack_patterns()
        
        if not patterns:
            return None
        
        df = pd.DataFrame(patterns)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        fig = px.scatter(
            df, 
            x='timestamp', 
            y='technique_name',
            title='Attack Patterns Timeline',
            hover_data=['description']
        )
        
        return fig
    
    def create_threat_dashboard(self):
        """Create comprehensive threat dashboard"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('IOC Types', 'Vulnerability Severity', 'CVSS Scores', 'Attack Tactics'),
            specs=[[{"type": "pie"}, {"type": "bar"}],
                   [{"type": "histogram"}, {"type": "bar"}]]
        )
        
        # IOC pie chart
        iocs = self.database.get_iocs()
        if iocs:
            ioc_types = [ioc['type'] for ioc in iocs]
            type_counts = Counter(ioc_types)
            fig.add_trace(
                go.Pie(labels=list(type_counts.keys()), values=list(type_counts.values())),
                row=1, col=1
            )
        
        # Vulnerability severity bar chart
        vulns = self.database.get_vulnerabilities()
        if vulns:
            severities = [vuln['severity'] for vuln in vulns]
            severity_counts = Counter(severities)
            fig.add_trace(
                go.Bar(x=list(severity_counts.keys()), y=list(severity_counts.values())),
                row=1, col=2
            )
            
            # CVSS score histogram
            cvss_scores = [vuln['cvss_score'] for vuln in vulns if vuln['cvss_score']]
            if cvss_scores:
                fig.add_trace(
                    go.Histogram(x=cvss_scores),
                    row=2, col=1
                )
        
        # Attack tactics bar chart
        patterns = self.database.get_attack_patterns()
        if patterns:
            all_tactics = []
            for pattern in patterns:
                if pattern['tactics']:
                    all_tactics.extend(pattern['tactics'].split(','))
            
            tactic_counts = Counter(all_tactics)
            fig.add_trace(
                go.Bar(x=list(tactic_counts.keys()), y=list(tactic_counts.values())),
                row=2, col=2
            )
        
        fig.update_layout(height=800, showlegend=False, title_text="Threat Intelligence Dashboard")
        return fig

class ThreatIntelligenceSystem:
    def __init__(self):
        self.extractor = ThreatIntelligenceExtractor()
        self.collector = ThreatDataCollector()
        self.processor = ThreatIntelligenceProcessor(self.extractor)
        self.database = ThreatDatabase(self.extractor)
        self.visualization = ThreatVisualization(self.database)
    
    def process_document(self, text: str, source: str = "Manual Input"):
        """Process a single document for threat intelligence"""
        results = self.processor.process_text(text, source)
        
        # Store results in database
        for ioc in results['iocs']:
            self.database.store_ioc(ioc)
        
        for vuln in results['vulnerabilities']:
            self.database.store_vulnerability(vuln)
        
        for pattern in results['attack_patterns']:
            self.database.store_attack_pattern(pattern)
        
        return results
    
    def collect_and_process_feeds(self):
        """Collect and process threat intelligence feeds"""
        # Collect MITRE data
        mitre_data = self.collector.collect_mitre_data()
        for technique in mitre_data:
            pattern = AttackPattern(
                technique_id=technique['technique_id'],
                technique_name=technique['technique_name'],
                description=technique['description'],
                tactics=technique['tactics'],
                mitre_id=technique['mitre_id'],
                source='MITRE',
                timestamp=datetime.now()
            )
            self.database.store_attack_pattern(pattern)
        
        # Collect CVE data
        cve_data = self.collector.collect_cve_data()
        for cve in cve_data:
            vuln = Vulnerability(
                cve_id=cve['cve_id'],
                description=cve['description'],
                severity=cve['severity'],
                cvss_score=cve['cvss_score'],
                affected_systems=cve['affected_systems'],
                source='NVD',
                timestamp=datetime.now()
            )
            self.database.store_vulnerability(vuln)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat intelligence report"""
        iocs = self.database.get_iocs()
        vulns = self.database.get_vulnerabilities()
        patterns = self.database.get_attack_patterns()
        
        report = {
            'summary': {
                'total_iocs': len(iocs),
                'total_vulnerabilities': len(vulns),
                'total_attack_patterns': len(patterns),
                'generation_time': datetime.now().isoformat()
            },
            'iocs': iocs,
            'vulnerabilities': vulns,
            'attack_patterns': patterns
        }
        
        return report

# Streamlit Web Interface
def create_web_interface():
    st.title("Cyber Threat Intelligence System")
    st.markdown("Extract IOCs, vulnerabilities, and attack patterns from threat intelligence sources")
    
    # Initialize system
    if 'threat_system' not in st.session_state:
        st.session_state.threat_system = ThreatIntelligenceSystem()
    
    system = st.session_state.threat_system
    
    # Sidebar
    st.sidebar.title("Options")
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Document Analysis", "Data Collection", "Visualizations", "Reports"])
    
    with tab1:
        st.header("Document Analysis")
        
        # Text input
        text_input = st.text_area("Enter threat intelligence text:", height=300)
        source_input = st.text_input("Source:", value="Manual Input")
        
        if st.button("Process Document"):
            if text_input:
                with st.spinner("Processing document..."):
                    results = system.process_document(text_input, source_input)
                
                st.success("Document processed successfully!")
                
                # Display results
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.subheader("IOCs Found")
                    for ioc in results['iocs']:
                        st.write(f"**{ioc.type}**: {ioc.value} (Confidence: {ioc.confidence:.2f})")
                
                with col2:
                    st.subheader("Vulnerabilities")
                    for vuln in results['vulnerabilities']:
                        st.write(f"**{vuln.cve_id}**: {vuln.severity}")
                
                with col3:
                    st.subheader("Attack Patterns")
                    for pattern in results['attack_patterns']:
                        st.write(f"**{pattern.technique_name}**: {pattern.technique_id}")
    
    with tab2:
        st.header("Data Collection")
        
        if st.button("Collect Threat Intelligence Feeds"):
            with st.spinner("Collecting threat intelligence feeds..."):
                system.collect_and_process_feeds()
            st.success("Threat intelligence feeds collected successfully!")
    
    with tab3:
        st.header("Visualizations")
        
        # IOC distribution
        ioc_chart = system.visualization.create_ioc_distribution_chart()
        if ioc_chart:
            st.plotly_chart(ioc_chart, use_container_width=True)
        
        # Vulnerability severity
        vuln_chart = system.visualization.create_vulnerability_severity_chart()
        if vuln_chart:
            st.plotly_chart(vuln_chart, use_container_width=True)
        
        # Attack pattern timeline
        timeline_chart = system.visualization.create_attack_pattern_timeline()
        if timeline_chart:
            st.plotly_chart(timeline_chart, use_container_width=True)
        
        # Comprehensive dashboard
        dashboard = system.visualization.create_threat_dashboard()
        if dashboard:
            st.plotly_chart(dashboard, use_container_width=True)
    
    with tab4:
        st.header("Reports")
        
        if st.button("Generate Report"):
            report = system.generate_report()
            
            # Display summary
            st.subheader("Summary")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total IOCs", report['summary']['total_iocs'])
            
            with col2:
                st.metric("Total Vulnerabilities", report['summary']['total_vulnerabilities'])
            
            with col3:
                st.metric("Total Attack Patterns", report['summary']['total_attack_patterns'])
            
            # Export options
            st.subheader("Export Options")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Export as JSON"):
                    st.download_button(
                        label="Download JSON Report",
                        data=json.dumps(report, indent=2, default=str),
                        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            with col2:
                if st.button("Export as CSV"):
                    # Create CSV data for IOCs
                    ioc_df = pd.DataFrame(report['iocs'])
                    csv_data = ioc_df.to_csv(index=False)
                    
                    st.download_button(
                        label="Download CSV Report",
                        data=csv_data,
                        file_name=f"iocs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )

# Example usage
if __name__ == "__main__":
    # Command line interface
    import argparse
    
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence System")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="Run mode")
    parser.add_argument("--text", help="Text to analyze")
    parser.add_argument("--source", default="CLI", help="Source of the text")
    parser.add_argument("--file", help="File to analyze")
    
    args = parser.parse_args()
    
    if args.mode == "web":
        # Run Streamlit web interface
        create_web_interface()
    else:
        # Run CLI interface
        system = ThreatIntelligenceSystem()
        
        if args.file:
            # Process file
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    text = f.read()
                
                print(f"Processing file: {args.file}")
                results = system.process_document(text, args.file)
                
                print(f"\nResults:")
                print(f"IOCs found: {len(results['iocs'])}")
                print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
                print(f"Attack patterns found: {len(results['attack_patterns'])}")
                
                # Display detailed results
                if results['iocs']:
                    print("\n=== IOCs ===")
                    for ioc in results['iocs']:
                        print(f"{ioc.type}: {ioc.value} (Confidence: {ioc.confidence:.2f})")
                
                if results['vulnerabilities']:
                    print("\n=== Vulnerabilities ===")
                    for vuln in results['vulnerabilities']:
                        print(f"{vuln.cve_id}: {vuln.severity}")
                
                if results['attack_patterns']:
                    print("\n=== Attack Patterns ===")
                    for pattern in results['attack_patterns']:
                        print(f"{pattern.technique_name} ({pattern.technique_id})")
                
            except Exception as e:
                print(f"Error processing file: {e}")
        
        elif args.text:
            # Process text
            print("Processing text...")
            results = system.process_document(args.text, args.source)
            
            print(f"\nResults:")
            print(f"IOCs found: {len(results['iocs'])}")
            print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
            print(f"Attack patterns found: {len(results['attack_patterns'])}")
            
            # Display detailed results
            if results['iocs']:
                print("\n=== IOCs ===")
                for ioc in results['iocs']:
                    print(f"{ioc.type}: {ioc.value} (Confidence: {ioc.confidence:.2f})")
            
            if results['vulnerabilities']:
                print("\n=== Vulnerabilities ===")
                for vuln in results['vulnerabilities']:
                    print(f"{vuln.cve_id}: {vuln.severity}")
            
            if results['attack_patterns']:
                print("\n=== Attack Patterns ===")
                for pattern in results['attack_patterns']:
                    print(f"{pattern.technique_name} ({pattern.technique_id})")
        
        else:
            # Interactive demo
            print("Cyber Threat Intelligence System - Interactive Demo")
            print("=" * 50)
            
            # Collect sample data
            print("Collecting threat intelligence feeds...")
            system.collect_and_process_feeds()
            
            # Process sample threat intelligence text
            sample_text = """
            The APT group has been observed using CVE-2024-1234 to gain initial access to target networks.
            The malware communicates with C2 server at 192.168.1.100 and downloads additional payloads from
            malicious-domain.com. The attack involves lateral movement using valid accounts (T1078) and
            establishes persistence through scheduled tasks. The SHA256 hash of the malware is 
            a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456. Email phishing campaigns
            targeting admin@company.com have been observed as part of the initial access vector.
            """
            
            print("\nProcessing sample threat intelligence text...")
            results = system.process_document(sample_text, "Sample Report")
            
            print(f"\nResults from sample text:")
            print(f"IOCs found: {len(results['iocs'])}")
            print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
            print(f"Attack patterns found: {len(results['attack_patterns'])}")
            
            # Generate report
            print("\nGenerating comprehensive report...")
            report = system.generate_report()
            
            print(f"\nThreat Intelligence Summary:")
            print(f"Total IOCs: {report['summary']['total_iocs']}")
            print(f"Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
            print(f"Total Attack Patterns: {report['summary']['total_attack_patterns']}")
            
            # Save report
            with open(f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"\nReport saved as threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            print("\nTo run the web interface, use: python threat_intelligence.py --mode web")

# Additional utility functions
class ThreatIntelligenceAPI:
    """REST API interface for the threat intelligence system"""
    
    def __init__(self, system: ThreatIntelligenceSystem):
        self.system = system
    
    def process_text_endpoint(self, text: str, source: str = "API"):
        """API endpoint for processing text"""
        try:
            results = self.system.process_document(text, source)
            return {
                'status': 'success',
                'data': {
                    'iocs': [self._serialize_ioc(ioc) for ioc in results['iocs']],
                    'vulnerabilities': [self._serialize_vulnerability(vuln) for vuln in results['vulnerabilities']],
                    'attack_patterns': [self._serialize_attack_pattern(pattern) for pattern in results['attack_patterns']]
                }
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def get_iocs_endpoint(self, limit: int = 100):
        """API endpoint for retrieving IOCs"""
        try:
            iocs = self.system.database.get_iocs(limit)
            return {
                'status': 'success',
                'data': iocs
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def get_vulnerabilities_endpoint(self, limit: int = 100):
        """API endpoint for retrieving vulnerabilities"""
        try:
            vulns = self.system.database.get_vulnerabilities(limit)
            return {
                'status': 'success',
                'data': vulns
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def get_attack_patterns_endpoint(self, limit: int = 100):
        """API endpoint for retrieving attack patterns"""
        try:
            patterns = self.system.database.get_attack_patterns(limit)
            return {
                'status': 'success',
                'data': patterns
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _serialize_ioc(self, ioc: IOC) -> Dict:
        """Serialize IOC object for API response"""
        return {
            'type': ioc.type,
            'value': ioc.value,
            'confidence': ioc.confidence,
            'source': ioc.source,
            'timestamp': ioc.timestamp.isoformat(),
            'context': ioc.context
        }
    
    def _serialize_vulnerability(self, vuln: Vulnerability) -> Dict:
        """Serialize Vulnerability object for API response"""
        return {
            'cve_id': vuln.cve_id,
            'description': vuln.description,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'affected_systems': vuln.affected_systems,
            'source': vuln.source,
            'timestamp': vuln.timestamp.isoformat()
        }
    
    def _serialize_attack_pattern(self, pattern: AttackPattern) -> Dict:
        """Serialize AttackPattern object for API response"""
        return {
            'technique_id': pattern.technique_id,
            'technique_name': pattern.technique_name,
            'description': pattern.description,
            'tactics': pattern.tactics,
            'mitre_id': pattern.mitre_id,
            'source': pattern.source,
            'timestamp': pattern.timestamp.isoformat()
        }

# Flask REST API implementation
try:
    from flask import Flask, request, jsonify
    
    def create_flask_app():
        """Create Flask application for REST API"""
        app = Flask(__name__)
        system = ThreatIntelligenceSystem()
        api = ThreatIntelligenceAPI(system)
        
        @app.route('/api/process', methods=['POST'])
        def process_text():
            data = request.get_json()
            if not data or 'text' not in data:
                return jsonify({'status': 'error', 'message': 'Missing text parameter'}), 400
            
            text = data['text']
            source = data.get('source', 'API')
            
            result = api.process_text_endpoint(text, source)
            status_code = 200 if result['status'] == 'success' else 400
            
            return jsonify(result), status_code
        
        @app.route('/api/iocs', methods=['GET'])
        def get_iocs():
            limit = request.args.get('limit', 100, type=int)
            result = api.get_iocs_endpoint(limit)
            return jsonify(result)
        
        @app.route('/api/vulnerabilities', methods=['GET'])
        def get_vulnerabilities():
            limit = request.args.get('limit', 100, type=int)
            result = api.get_vulnerabilities_endpoint(limit)
            return jsonify(result)
        
        @app.route('/api/attack-patterns', methods=['GET'])
        def get_attack_patterns():
            limit = request.args.get('limit', 100, type=int)
            result = api.get_attack_patterns_endpoint(limit)
            return jsonify(result)
        
        @app.route('/api/report', methods=['GET'])
        def get_report():
            try:
                report = system.generate_report()
                return jsonify({'status': 'success', 'data': report})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        return app
    
except ImportError:
    print("Flask not installed. REST API functionality will not be available.")
    def create_flask_app():
        return None

# Configuration file example
CONFIG_EXAMPLE = '''
# Threat Intelligence System Configuration
# Copy this to config.py and modify as needed

# Database Configuration
DATABASE_PATH = "threat_intelligence.db"

# NLP Models Configuration
SPACY_MODEL = "en_core_web_sm"
BERT_MODEL = "dbmdz/bert-large-cased-finetuned-conll03-english"

# API Configuration
OPENAI_API_KEY = "your_openai_api_key_here"  # For LangChain summarization

# Data Sources
MITRE_API_URL = "https://attack.mitre.org/api/"
CISA_API_URL = "https://www.cisa.gov/api/"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/"

# Confidence Thresholds
IOC_CONFIDENCE_THRESHOLD = 0.6
VULNERABILITY_CONFIDENCE_THRESHOLD = 0.7

# Rate Limiting
API_RATE_LIMIT = 100  # requests per hour
'''

# Installation requirements
REQUIREMENTS = '''
# Requirements for Cyber Threat Intelligence System
# Install with: pip install -r requirements.txt

# Core dependencies
spacy>=3.4.0
transformers>=4.20.0
torch>=1.12.0
langchain>=0.0.200
pandas>=1.5.0
numpy>=1.23.0
scikit-learn>=1.1.0

# Database
sqlite3

# Visualization
matplotlib>=3.5.0
seaborn>=0.11.0
plotly>=5.10.0

# Web interface
streamlit>=1.12.0

# API (optional)
flask>=2.2.0
requests>=2.28.0

# NLP models
# Run after installing spacy:
# python -m spacy download en_core_web_sm

# Additional security libraries
cryptography>=3.4.0
python-magic>=0.4.0
'''

# Documentation
DOCUMENTATION = '''
# Cyber Threat Intelligence System Documentation

## Overview
This system extracts Indicators of Compromise (IOCs), vulnerabilities, and attack patterns from threat intelligence sources using Natural Language Processing techniques.

## Features
- **IOC Extraction**: Extract IP addresses, domains, URLs, file hashes, CVEs, and more
- **Vulnerability Analysis**: Identify and categorize security vulnerabilities
- **Attack Pattern Recognition**: Detect MITRE ATT&CK techniques and tactics
- **Dynamic Database**: Store and manage threat intelligence data
- **Visualization**: Interactive charts and dashboards
- **Multiple Interfaces**: CLI, Web UI, and REST API

## Installation
1. Install Python 3.8+
2. Install dependencies: `pip install -r requirements.txt`
3. Download spaCy model: `python -m spacy download en_core_web_sm`
4. Run the system: `python threat_intelligence.py`

## Usage Examples

### Command Line Interface
```bash
# Process a text file
python threat_intelligence.py --file threat_report.txt

# Process text directly
python threat_intelligence.py --text "CVE-2024-1234 affects system at 192.168.1.1"

# Run web interface
python threat_intelligence.py --mode web
```

### Web Interface
1. Run: `streamlit run threat_intelligence.py -- --mode web`
2. Open browser to http://localhost:8501
3. Use the tabs to analyze documents, collect feeds, view visualizations, and generate reports

### REST API
```python
from flask import Flask
app = create_flask_app()
app.run(debug=True)
```

API Endpoints:
- POST /api/process - Process text for threat intelligence
- GET /api/iocs - Retrieve IOCs
- GET /api/vulnerabilities - Retrieve vulnerabilities
- GET /api/attack-patterns - Retrieve attack patterns
- GET /api/report - Generate comprehensive report

## Configuration
Create a config.py file with your API keys and preferences:
```python
OPENAI_API_KEY = "your_key_here"
IOC_CONFIDENCE_THRESHOLD = 0.6
```

## Database Schema
The system uses SQLite with three main tables:
- `iocs`: Stores indicators of compromise
- `vulnerabilities`: Stores vulnerability information
- `attack_patterns`: Stores MITRE ATT&CK techniques

## Extending the System
- Add new IOC patterns in `setup_patterns()`
- Implement additional data sources in `ThreatDataCollector`
- Create custom visualization in `ThreatVisualization`
- Add new NLP models in `setup_nlp_models()`

## Performance Optimization
- Use GPU acceleration for transformer models
- Implement caching for frequent queries
- Batch process large documents
- Use async processing for real-time feeds

## Security Considerations
- Validate all input data
- Implement rate limiting for API endpoints
- Use secure database connections
- Encrypt sensitive configuration data
'''

print("Cyber Threat Intelligence System")
print("=" * 40)
print("Complete system for extracting IOCs, vulnerabilities, and attack patterns")
print("Features: NLP processing, dynamic database, visualization, and multiple interfaces")
print()
print("To get started:")
print("1. Install requirements: pip install -r requirements.txt")
print("2. Download spaCy model: python -m spacy download en_core_web_sm")
print("3. Run the system: python threat_intelligence.py")
print("4. For web interface: python threat_intelligence.py --mode web")