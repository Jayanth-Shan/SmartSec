# SmartSec: AI-Powered Web Vulnerability Scanner

SmartSec is a modular web-based cybersecurity assistant designed to perform network vulnerability scans directly from a browser — **no installation required**.  
It integrates traditional security tools (like Nessus) with an AI-powered backend that interprets scan results, identifies potential threats, and provides actionable mitigation steps.

---

## 🚀 Features

- **Web-based scanning:** Scan IP addresses and network hosts without local installations.
- **Nessus integration:** Automates vulnerability scanning and report generation.
- **AI-driven analysis:** A trained model evaluates scan data and classifies system vulnerabilities.
- **Remediation guidance:** Recommends step-by-step solutions for each detected issue.
- **Future scope:** Enable automated script execution to patch vulnerabilities and expand the integrated toolset.

---

## 🧠 System Architecture

Frontend (React + Vite + Tailwind)
↓
Backend (Python - Flask/Django + AI Model)
↓
Nessus / Vulnerability Scanner → Generates Reports (.nessus/.xml)
↓
AI Model → Parses + Analyzes Vulnerabilities
↓
Web UI → Displays Recommendations + Fix Steps


---

## 📁 Folder Structure

SmartSec/
│
├── backend/
│ ├── app.py # Main backend service entry
│ ├── django_rag_chatbot.py # AI-driven RAG chatbot for analysis
│ ├── requirements.txt # Python dependencies
│ ├── cybersec_knowledge.db # Knowledge base / fine-tuned dataset
│ └── .env # Environment variables (API keys, secrets)
│
├── frontend/
│ ├── src/
│ │ ├── components/ # React UI components
│ │ ├── assets/ # Images, icons, static files
│ │ └── App.tsx, main.tsx # Application entry points
│ ├── package.json # Frontend dependencies
│ ├── vite.config.ts # Build configuration
│ └── tailwind.config.ts # Styling setup
│
└── README.md 


---

## ⚙️ Installation & Setup

### 🐍 Backend Setup (Python)
```bash
cd backend
python -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Make sure to create a .env file in the backend/ directory containing:

NESSUS_API_KEY=your_key_here
MODEL_PATH=models/your_model.pkl

💻 Frontend Setup (React + Vite)
cd frontend
npm install
npm run dev

By default, the frontend runs at http://localhost:5173 and communicates with the backend on http://localhost:5000.

🧩 AI Model Details

The backend integrates a fine-tuned AI model trained on public vulnerability datasets such as NVD and VirusTotal.
It performs:

Pattern recognition on Nessus reports

Risk categorization (Critical, High, Medium, Low)

Threat explanation generation using contextual knowledge base

Recommendation of countermeasures

🧰 Tools & Technologies
Layer	Technology
Frontend	React, Vite, TailwindCSS, TypeScript
Backend	Python (Flask/Django), SQLite
AI	RAG (Retrieval-Augmented Generation)
Scanning	Nessus, Nmap (future), OpenVAS (planned)

🧪 Future Enhancements

 Local automation scripts to fix vulnerabilities

 Integration with Nmap and OpenVAS

 Role-based authentication for multi-user environments

 Real-time reporting dashboard

 Docker containerization for easy deployment
