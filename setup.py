#!/usr/bin/env python3
"""
Setup script for Cyber Threat Intelligence System
Automatically installs dependencies and downloads required models
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Command: {command}")
        print(f"   Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    python_version = sys.version_info
    if python_version < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {python_version.major}.{python_version.minor}")
        return False
    
    print(f"✅ Python {python_version.major}.{python_version.minor} is compatible")
    return True

def install_requirements():
    """Install Python dependencies"""
    return run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing Python dependencies"
    )

def download_spacy_model():
    """Download spaCy language model"""
    return run_command(
        f"{sys.executable} -m spacy download en_core_web_sm",
        "Downloading spaCy English model"
    )

def download_nltk_data():
    """Download NLTK data"""
    commands = [
        f"{sys.executable} -c \"import nltk; nltk.download('punkt')\"",
        f"{sys.executable} -c \"import nltk; nltk.download('stopwords')\"",
        f"{sys.executable} -c \"import nltk; nltk.download('vader_lexicon')\"",
    ]
    
    for cmd in commands:
        if not run_command(cmd, "Downloading NLTK data"):
            return False
    return True

def create_config_file():
    """Create default configuration file"""
    config_content = '''# Cyber Threat Intelligence System Configuration
# Modify these settings as needed

# Database Configuration
DATABASE_PATH = "threat_intelligence.db"

# NLP Models
SPACY_MODEL = "en_core_web_sm"
BERT_MODEL = "dbmdz/bert-large-cased-finetuned-conll03-english"

# API Keys (replace with your actual keys)
OPENAI_API_KEY = ""  # Required for LangChain summarization
HF_TOKEN = ""        # Optional: Hugging Face token for model access

# Data Sources
MITRE_API_URL = "https://attack.mitre.org/api/"
CISA_API_URL = "https://www.cisa.gov/api/"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/"

# Confidence Thresholds
IOC_CONFIDENCE_THRESHOLD = 0.6
VULNERABILITY_CONFIDENCE_THRESHOLD = 0.7
ATTACK_PATTERN_CONFIDENCE_THRESHOLD = 0.5

# Rate Limiting
API_RATE_LIMIT = 100  # requests per hour
REQUEST_TIMEOUT = 30  # seconds

# Processing Settings
MAX_TEXT_LENGTH = 100000  # Maximum text length to process
BATCH_SIZE = 32           # Batch size for model inference
USE_GPU = True            # Use GPU if available

# Visualization Settings
PLOT_STYLE = "plotly_white"
COLOR_SCHEME = "viridis"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "threat_intelligence.log"
'''
    
    try:
        with open("config.py", "w") as f:
            f.write(config_content)
        print("✅ Created default configuration file (config.py)")
        return True
    except Exception as e:
        print(f"❌ Failed to create config file: {e}")
        return False

def create_sample_data():
    """Create sample threat intelligence data for testing"""
    sample_data = '''# Sample Threat Intelligence Text for Testing

## APT Campaign Analysis Report

### Executive Summary
A sophisticated APT group has been observed targeting financial institutions using a multi-stage attack campaign. The group utilizes CVE-2024-1234 for initial access and maintains persistence through scheduled tasks (T1053).

### Technical Analysis

#### Initial Access
The threat actors gained initial access through spear-phishing emails containing malicious attachments. The payload connects to command and control servers at the following locations:
- 192.168.1.100 (primary C2)
- malicious-domain.com (backup C2)
- https://evil-site.net/admin/panel

#### Malware Analysis
The main payload has been identified with the following characteristics:
- SHA256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
- MD5: 1234567890abcdef1234567890abcdef
- File size: 2.5 MB
- Compilation timestamp: 2024-01-15 14:30:00

#### Attack Techniques
The following MITRE ATT&CK techniques were observed:
- T1078: Valid Accounts - Used for lateral movement
- T1053: Scheduled Task/Job - For persistence
- T1005: Data from Local System - For data collection
- T1041: Exfiltration Over C2 Channel - For data theft

#### Indicators of Compromise
- Email: attacker@malicious-domain.com
- Registry key: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateService
- File path: C:\\Users\\Public\\temp\\malware.exe

#### Vulnerabilities Exploited
- CVE-2024-1234: Remote Code Execution in Office Suite (CVSS: 9.8)
- CVE-2024-5678: Privilege Escalation in Windows Service (CVSS: 7.2)

### Recommendations
1. Patch all systems against CVE-2024-1234 and CVE-2024-5678
2. Block network traffic to identified C2 servers
3. Monitor for the presence of identified file hashes
4. Implement email security controls to prevent phishing
'''
    
    try:
        with open("sample_threat_data.txt", "w") as f:
            f.write(sample_data)
        print("✅ Created sample threat intelligence data (sample_threat_data.txt)")
        return True
    except Exception as e:
        print(f"❌ Failed to create sample data: {e}")
        return False

def create_run_script():
    """Create convenient run scripts"""
    
    # Python run script
    run_script = '''#!/usr/bin/env python3
"""
Convenient launcher for Cyber Threat Intelligence System
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_intelligence import *

if __name__ == "__main__":
    # Check if running in web mode
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        print("🚀 Starting Cyber Threat Intelligence Web Interface...")
        print("   Open your browser to: http://localhost:8501")
        print("   Press Ctrl+C to stop")
        
        # Run streamlit
        import streamlit.web.cli as stcli
        sys.argv = ["streamlit", "run", "threat_intelligence.py", "--", "--mode", "web"]
        stcli.main()
    else:
        # Run CLI version
        print("🚀 Starting Cyber Threat Intelligence CLI...")
        exec(open("threat_intelligence.py").read())
'''
    
    try:
        with open("run.py", "w") as f:
            f.write(run_script)
        
        # Make executable on Unix systems
        if os.name != 'nt':
            os.chmod("run.py", 0o755)
        
        print("✅ Created run script (run.py)")
        return True
    except Exception as e:
        print(f"❌ Failed to create run script: {e}")
        return False

def verify_installation():
    """Verify that all components are installed correctly"""
    print("\n🔍 Verifying installation...")
    
    # Test imports
    test_imports = [
        "spacy",
        "transformers",
        "torch",
        "pandas",
        "numpy",
        "matplotlib",
        "plotly",
        "streamlit"
    ]
    
    failed_imports = []
    
    for module in test_imports:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError:
            print(f"   ❌ {module}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n❌ Some modules failed to import: {failed_imports}")
        print("   Please check the installation and try again")
        return False
    
    # Test spaCy model
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        print("   ✅ spaCy English model loaded successfully")
    except OSError:
        print("   ❌ spaCy English model not found")
        return False
    
    print("\n✅ All components verified successfully!")
    return True

def main():
    """Main setup function"""
    print("🚀 Cyber Threat Intelligence System Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("❌ Failed to install requirements. Please check your internet connection.")
        sys.exit(1)
    
    # Download models
    if not download_spacy_model():
        print("⚠️  Warning: spaCy model download failed. NLP features may not work properly.")
    
    if not download_nltk_data():
        print("⚠️  Warning: NLTK data download failed. Some text processing features may not work.")
    
    # Create configuration files
    create_config_file()
    create_sample_data()
    create_run_script()
    
    # Verify installation
    if verify_installation():
        print("\n🎉 Setup completed successfully!")
        print("\nNext steps:")
        print("1. Edit config.py to add your API keys")
        print("2. Run the system:")
        print("   - CLI mode: python threat_intelligence.py")
        print("   - Web mode: python run.py web")
        print("   - Test with sample data: python threat_intelligence.py --file sample_threat_data.txt")
        print("\n📚 Check the documentation in the main script for more details")
    else:
        print("\n❌ Setup completed with errors. Please check the messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()