# 🛡️ Cyber Threat Intelligence using NLP

Extract IOCs (Indicators of Compromise), vulnerabilities, and attack patterns from cybersecurity reports, blogs, and articles using NLP and AI-based techniques.

---

## 🚀 Goal

To build an end-to-end AI-powered system that can:
- Extract threat intelligence entities like **IOCs**, **vulnerabilities**, and **attack patterns**
- Summarize threat reports
- Populate a **dynamic threat database**
- Offer insightful **visualizations** and reports for security analysts

---

## 🧠 Technologies Used

- **🧾 Named Entity Recognition**:  
  - `BERT`, `dbmdz/bert-large-cased-finetuned-conll03-english` for entity extraction  
  - Custom models and `spaCy` for preprocessing

- **📚 LLMs + LangChain**:
  - `OpenAI`, `LangChain` for summarization & keyword extraction

- **📄 Data Sources**:
  - MITRE ATT&CK reports, CISA alerts, public cyber threat blogs, etc.

- **📊 Visualization**:
  - `Matplotlib`, `Seaborn`, `Plotly` for insights and attack pattern mapping

- **📦 Backend**:
  - `SQLite` (local DB) for storing IOCs, vulnerabilities, timestamps, and sources

- **🌐 Web Interface**:
  - `Streamlit` for an interactive UI

---

## 🧰 Features

- 📄 Analyze raw text from threat intelligence sources
- 🧠 Extract:
  - IPs, URLs, file hashes (IOCs)
  - CVEs and vulnerabilities
  - Attack techniques and tactics
- 🗂️ Automatically classify and summarize threat documents
- 📈 Visual dashboard with trends and frequency charts
- 📬 Report export in structured format

---

## 🛠️ Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/yourusername/cyber-threat-nlp.git
   cd cyber-threat-nlp
