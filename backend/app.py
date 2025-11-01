from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import asyncio
import os
import sys
import json
import traceback
import logging
from datetime import datetime
import csv
import io
from openai import OpenAI

# Load environment variables from .env file
load_dotenv()

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import your Django chatbot
try:
    from django_rag_chatbot import DjangoRAGChatbot
    print("✅ Successfully imported DjangoRAGChatbot")
except ImportError as e:
    print(f"❌ Failed to import DjangoRAGChatbot: {e}")
    print("Make sure django_rag_chatbot.py is in the backend directory")
    sys.exit(1)

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8080", "http://127.0.0.1:8080"])

# Configure logging for Windows
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chatbot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Global variables
django_bot = None
openai_client = None
active_sessions = {}

def check_api_keys():
    """Check if required API keys are set"""
    required_keys = ["GROQ_API_KEY"]
    optional_keys = ["VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "NVD_API_KEY", "ALIENVAULT_API_KEY", "OPENAI_API_KEY"]
    
    missing_required = [key for key in required_keys if not os.environ.get(key)]
    available_optional = [key for key in optional_keys if os.environ.get(key)]
    
    if missing_required:
        print(f"❌ Missing required API keys: {', '.join(missing_required)}")
        print("Please add them to your .env file")
        return False
    
    print("✅ Required API keys found")
    if available_optional:
        print(f"✅ Optional API keys found: {', '.join(available_optional)}")
    else:
        print("⚠️  No optional API keys found (some features will be limited)")
    
    return True

def initialize_openai():
    """Initialize OpenAI client"""
    global openai_client
    
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        print("⚠️ Warning: OPENAI_API_KEY not found in environment variables")
        print("   Vulnerability analysis feature will be disabled")
        return False
    
    try:
        openai_client = OpenAI(api_key=openai_api_key)
        print("✅ OpenAI client initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize OpenAI: {e}")
        return False

def initialize_chatbot():
    """Initialize the Django RAG Chatbot"""
    global django_bot
    
    if not check_api_keys():
        return False
    
    try:
        print("🔧 Initializing Django RAG Chatbot...")
        django_bot = DjangoRAGChatbot()
        
        # Enhanced cybersecurity knowledge base
        enhanced_knowledge = [
            {"category": "authentication", "text": "Multi-Factor Authentication (MFA) should use hardware security keys (FIDO2/WebAuthn), TOTP authenticator apps, or SMS as backup. Avoid SMS-only MFA due to SIM swapping attacks. Implement adaptive authentication based on risk factors like location, device, and behavior patterns.", "tags": "mfa,authentication,fido2,webauthn"},
            {"category": "network_security", "text": "Zero Trust Network Architecture assumes no implicit trust and continuously validates every transaction. Implement micro-segmentation using software-defined perimeters, enforce least-privilege access, and monitor all network traffic with behavioral analysis and anomaly detection.", "tags": "zero_trust,network,microsegmentation"},
            {"category": "vulnerability_management", "text": "Vulnerability management should prioritize based on CVSS score, exploitability (EPSS), asset criticality, and threat intelligence. Critical vulnerabilities (CVSS 9-10) require patching within 24-72 hours. Use automated scanning tools like Nessus, Qualys, or OpenVAS integrated with patch management systems.", "tags": "vulnerability,cvss,epss,scanning"},
            {"category": "incident_response", "text": "Incident response follows NIST framework: Preparation, Detection/Analysis, Containment/Eradication/Recovery, and Post-Incident Activity. Maintain updated playbooks, conduct tabletop exercises quarterly, establish clear communication channels, and integrate with SIEM/SOAR platforms.", "tags": "incident_response,nist,playbooks,siem,soar"},
            {"category": "threat_hunting", "text": "Proactive threat hunting uses hypothesis-driven investigations based on threat intelligence, IOCs, and behavioral analytics. Hunt for MITRE ATT&CK techniques, analyze process execution patterns, network connections, file system changes, and registry modifications.", "tags": "threat_hunting,mitre_attack,iocs,behavioral_analytics"},
            {"category": "shodan_osint", "text": "Shodan is a search engine for Internet-connected devices. Use it to discover exposed services, identify misconfigurations, and assess attack surface. Common searches include default credentials, open databases, and vulnerable services. Always ensure you have permission before scanning.", "tags": "shodan,osint,reconnaissance,network_scanning"},
        ]
        
        django_bot.add_documents(enhanced_knowledge)
        
        print("✅ Django RAG Chatbot initialized successfully!")
        print(f"📊 Knowledge base loaded with {len(enhanced_knowledge)} entries")
        logger.info("Chatbot initialization completed")
        return True
        
    except Exception as e:
        print(f"❌ Failed to initialize chatbot: {str(e)}")
        logger.error(f"Chatbot initialization failed: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def create_prompt_from_csv_data(csv_data):
    """Create GPT prompt from CSV data"""
    prompt = (
        "You are a cybersecurity analyst.\n"
        "Based on the following scan findings, identify realistic vulnerabilities that could exist.\n"
        "For each vulnerability, provide:\n"
        "- vulnerability (short name)\n"
        "- cvss_score (0.0 - 10.0)\n"
        "- severity (Critical, High, Medium, Low)\n"
        "- cve_id (e.g. CVE-2021-1234, or 'N/A')\n"
        "- cwe_id (e.g. CWE-89, or 'N/A')\n\n"
        "Return a JSON array in this format:\n"
        "[\n"
        "  {\n"
        "    \"vulnerability\": \"SQL Injection\",\n"
        "    \"cvss_score\": 9.8,\n"
        "    \"severity\": \"Critical\",\n"
        "    \"cve_id\": \"CVE-2019-1234\",\n"
        "    \"cwe_id\": \"CWE-89\"\n"
        "  }\n"
        "]\n\n"
        "Here are the scan findings:\n\n"
    )
    
    try:
        # Parse CSV data
        reader = csv.DictReader(io.StringIO(csv_data))
        
        for idx, row in enumerate(reader):
            finding = f"Finding {idx + 1}:\n"
            finding += f"Name: {row.get('Name', row.get('Plugin Name', ''))}\n"
            finding += f"Synopsis: {row.get('Synopsis', '')}\n"
            finding += f"Description: {row.get('Description', '')}\n"
            finding += f"Plugin Output: {row.get('Plugin Output', row.get('Output', ''))}\n\n"
            prompt += finding
            
            # Limit prompt size to avoid token limits
            if len(prompt) > 7000:
                prompt += "\n(Truncated due to size limits)\n"
                break
        
        return prompt
    except Exception as e:
        logger.error(f"Error parsing CSV data: {e}")
        return prompt + "\n(Error parsing CSV data)\n"

def call_openai_for_vulnerabilities(prompt):
    """Call OpenAI API for vulnerability analysis"""
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=2000
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return ""

def parse_vulnerability_json(response):
    """Parse GPT JSON response"""
    try:
        # Find JSON array in response
        start = response.find("[")
        end = response.rfind("]") + 1
        
        if start == -1 or end == 0:
            logger.error("No JSON array found in response")
            return []
        
        json_str = response[start:end]
        vulnerabilities = json.loads(json_str)
        
        # Validate structure
        valid_vulnerabilities = []
        for vuln in vulnerabilities:
            if isinstance(vuln, dict) and 'vulnerability' in vuln:
                # Ensure all required fields exist
                vuln.setdefault('cvss_score', 0.0)
                vuln.setdefault('severity', 'Unknown')
                vuln.setdefault('cve_id', 'N/A')
                vuln.setdefault('cwe_id', 'N/A')
                valid_vulnerabilities.append(vuln)
        
        return valid_vulnerabilities
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return []
    except Exception as e:
        logger.error(f"Failed to parse GPT response: {e}")
        return []

# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    api_status = {
        'groq': bool(os.environ.get("GROQ_API_KEY")),
        'virustotal': bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        'shodan': bool(os.environ.get("SHODAN_API_KEY")),
        'nvd': bool(os.environ.get("NVD_API_KEY")),
        'openai': bool(os.environ.get("OPENAI_API_KEY")),
    }
    
    return jsonify({
        'status': 'healthy',
        'chatbot_ready': django_bot is not None,
        'openai_ready': openai_client is not None,
        'api_keys_available': api_status,
        'platform': 'Windows',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/chat', methods=['POST'])
def chat_endpoint():
    """Main chat endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        user_message = data.get('message', '').strip()
        conversation_id = data.get('conversation_id', 'default')
        
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
            
        if not django_bot:
            return jsonify({
                'error': 'Chatbot not initialized',
                'response': "I'm sorry, but my backend services are not available right now. Please check the server logs and try again."
            }), 500
        
        logger.info(f"Processing message from session {conversation_id}: {user_message[:100]}...")
        
        # Windows-specific asyncio setup
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run the chatbot response generation
            bot_response = loop.run_until_complete(
                django_bot.get_response(user_message)
            )
            
            # Manage session history
            if conversation_id not in active_sessions:
                active_sessions[conversation_id] = {
                    'messages': [],
                    'created': datetime.now().isoformat()
                }
            
            active_sessions[conversation_id]['messages'].append({
                'user': user_message,
                'bot': bot_response,
                'timestamp': datetime.now().isoformat()
            })
            
            # Keep only last 10 messages per session
            if len(active_sessions[conversation_id]['messages']) > 10:
                active_sessions[conversation_id]['messages'] = active_sessions[conversation_id]['messages'][-10:]
            
            logger.info(f"Generated response: {len(bot_response)} characters")
            
            return jsonify({
                'response': bot_response,
                'status': 'success',
                'conversation_id': conversation_id,
                'timestamp': datetime.now().isoformat()
            })
            
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        
        return jsonify({
            'error': str(e),
            'response': "I encountered an error while processing your request. Please check the server logs and try again.",
            'status': 'error'
        }), 500

@app.route('/api/analyze-vulnerabilities', methods=['POST'])
def analyze_vulnerabilities():
    """Analyze vulnerabilities from CSV data"""
    try:
        data = request.get_json()
        
        if not data or 'csv_data' not in data:
            return jsonify({'error': 'CSV data is required'}), 400
        
        if not openai_client:
            return jsonify({
                'error': 'OpenAI not available. Please check your OPENAI_API_KEY in the .env file.',
                'vulnerabilities': []
            }), 500
        
        csv_data = data['csv_data']
        filename = data.get('filename', 'scan.csv')
        
        logger.info(f"Analyzing vulnerabilities from file: {filename}")
        
        # Create prompt from CSV data
        prompt = create_prompt_from_csv_data(csv_data)
        
        # Call OpenAI
        gpt_response = call_openai_for_vulnerabilities(prompt)
        
        if not gpt_response:
            return jsonify({
                'error': 'Failed to get response from OpenAI',
                'vulnerabilities': []
            }), 500
        
        # Parse vulnerabilities
        vulnerabilities = parse_vulnerability_json(gpt_response)
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
        
        return jsonify({
            'vulnerabilities': vulnerabilities,
            'filename': filename,
            'total_count': len(vulnerabilities),
            'status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Error in analyze_vulnerabilities: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'vulnerabilities': []
        }), 500

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def clear_session(session_id):
    """Clear a conversation session"""
    if session_id in active_sessions:
        del active_sessions[session_id]
        logger.info(f"Cleared session: {session_id}")
        return jsonify({'message': 'Session cleared'})
    else:
        return jsonify({'error': 'Session not found'}), 404

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Django RAG Chatbot Backend Server")
    print("=" * 60)
    
    # Initialize OpenAI
    openai_initialized = initialize_openai()
    
    if initialize_chatbot():
        print(f"✅ Server starting on Windows")
        print(f"🌐 Backend API: http://localhost:5000")
        print(f"📊 Health Check: http://localhost:5000/api/health")
        print(f"💬 Chat Endpoint: http://localhost:5000/api/chat")
        if openai_initialized:
            print(f"🔍 Vulnerability Analysis: http://localhost:5000/api/analyze-vulnerabilities")
        else:
            print(f"⚠️  Vulnerability Analysis: DISABLED (OpenAI API key missing)")
        print(f"📝 Logs: chatbot.log")
        print("=" * 60)
        
        app.run(
            debug=True, 
            host='0.0.0.0', 
            port=5000,
            threaded=True,
            use_reloader=False
        )
    else:
        print("❌ Failed to initialize chatbot. Please check your .env file and API keys.")
        input("Press Enter to exit...")
