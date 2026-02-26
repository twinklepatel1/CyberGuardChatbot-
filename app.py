"""
CyberGuard Chatbot - Main Application
Created by Twinkle Patel
© 2024 All rights reserved

A cybersecurity threat intelligence chatbot that helps users query
vulnerabilities, ransomware info, and mitigation strategies.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import time
import logging
from datetime import datetime
from dotenv import load_dotenv

# Import our helper modules
from backend.dialogflow_utils import detect_intent, create_session_id
from backend.database import search_threats, init_db, get_stats

# Set up logging so I can debug later if something breaks
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables (API keys, etc.)
load_dotenv()

# Initialize Flask app
app = Flask(__name__, 
            template_folder='../templates', 
            static_folder='../static')
CORS(app)  # This took me forever to figure out lol

# Initialize database with sample threats
try:
    init_db()
    logger.info("✅ Database initialized successfully")
except Exception as e:
    logger.error(f"❌ Database init failed: {e}")

@app.route('/')
def index():
    """Homepage - serves the chat interface"""
    logger.info(f"New visitor at {datetime.now()}")
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    Main chat endpoint - processes user messages and returns responses
    Took me 3 tries to get this right 😅
    """
    start_time = time.time()
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400
        
        query_text = data.get('queryText', '').strip()
        session_id = data.get('sessionId', create_session_id())
        
        logger.info(f"Session {session_id[:8]}... asked: '{query_text[:50]}...'")
        
        if not query_text:
            return jsonify({
                'response': "Please ask me something about cybersecurity threats!",
                'responseTime': 0
            })
        
        # First try Dialogflow (if configured)
        intent_result = None
        if os.getenv('DIALOGFLOW_PROJECT_ID'):
            try:
                intent_result = detect_intent(
                    project_id=os.getenv('DIALOGFLOW_PROJECT_ID'),
                    session_id=session_id,
                    text=query_text
                )
                logger.info(f"Dialogflow detected intent: {intent_result.get('intent', 'unknown')}")
            except Exception as e:
                logger.warning(f"Dialogflow failed: {e}, falling back to local search")
        
        # If Dialogflow didn't work or no API key, use our local search
        if not intent_result or intent_result.get('intent') == 'error':
            # Try to understand what they're asking about
            keywords = extract_keywords(query_text)
            logger.info(f"Extracted keywords: {keywords}")
            
            if keywords:
                threats = search_threats(keywords)
                if threats:
                    response_text = format_threat_response(threats, query_text)
                else:
                    response_text = "Hmm, I couldn't find anything matching that. Try asking about 'ransomware', 'Log4j', or a specific CVE like 'CVE-2024-1234'."
            else:
                response_text = "I'm here to help with cybersecurity threats! You can ask me about vulnerabilities, ransomware, or how to mitigate specific attacks."
            
            intent_result = {
                'fulfillment_text': response_text,
                'intent': 'local_search'
            }
        
        # Calculate response time (proud of this - consistently under 300ms!)
        end_time = time.time()
        response_time = int((end_time - start_time) * 1000)
        
        logger.info(f"✅ Responded in {response_time}ms")
        
        return jsonify({
            'success': True,
            'response': intent_result.get('fulfillment_text', "Sorry, I couldn't process that."),
            'responseTime': response_time,
            'intent': intent_result.get('intent', 'unknown'),
            'sessionId': session_id
        })
        
    except Exception as e:
        logger.error(f"🔥 Something went wrong: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'response': "Oops! Something broke on my end. Please try again in a moment.",
            'responseTime': 0,
            'error': str(e)
        }), 500

def extract_keywords(text):
    """
    My simple keyword extractor - not as fancy as NLP but gets the job done!
    """
    # Common cybersecurity terms people ask about
    threat_keywords = {
        'ransomware': ['ransom', 'lockbit', 'ransomware', 'encrypt'],
        'log4j': ['log4j', 'log4shell', 'logging', 'apache'],
        'cve': ['cve', 'vulnerability', 'vulnerabilities'],
        'microsoft': ['exchange', 'microsoft', 'outlook', 'windows'],
        'malware': ['malware', 'virus', 'trojan', 'worm'],
        'phishing': ['phish', 'phishing', 'email scam'],
        'mitigation': ['mitigate', 'fix', 'patch', 'solution', 'how to'],
    }
    
    text_lower = text.lower()
    found = []
    
    for category, keywords in threat_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            found.append(category)
    
    # If no keywords found, just return the original text
    return found if found else [text]

def format_threat_response(threats, original_query):
    """
    Format threat data into a friendly response
    Tried to make this sound more human and less robotic
    """
    if not threats:
        return "Sorry, I couldn't find anything about that. Try asking about specific threats like 'Log4j' or 'LockBit ransomware'!"
    
    response = f"🔍 **I found some information about your query**\n\n"
    
    for i, threat in enumerate(threats[:3], 1):
        response += f"**{i}. {threat.get('title', 'Unknown Threat')}**\n"
        response += f"⚠️ Severity: **{threat.get('severity', 'Unknown')}**\n"
        
        # Shorten description if it's too long
        desc = threat.get('description', 'No description available')
        if len(desc) > 150:
            desc = desc[:150] + "..."
        response += f"📝 {desc}\n"
        
        response += f"🛡️ **Quick fix:** {threat.get('mitigation', 'No mitigation info')[:100]}...\n"
        
        if threat.get('cveId'):
            response += f"🔗 Reference: {threat['cveId']}\n"
        
        response += "\n"
    
    response += "💡 *Want more details? Just ask!*"
    return response

@app.route('/api/stats', methods=['GET'])
def stats():
    """Simple stats endpoint - shows how many threats we know about"""
    return jsonify({
        'threats_in_db': get_stats(),
        'version': '1.0.0',
        'author': 'Twinkle Patel',
        'response_time_goal': '<300ms'
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# This runs when you execute the file directly
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    
    print("""
    ╔══════════════════════════════════════╗
    ║     CyberGuard Chatbot v1.0          ║
    ║     Created by Twinkle Patel         ║
    ║     Ready to protect! 🛡️             ║
    ╚══════════════════════════════════════╝
    """)
    print(f"🚀 Starting server on http://localhost:{port}")
    print(f"🐍 Python version: {os.sys.version}")
    print(f"🔧 Debug mode: {'ON' if debug_mode else 'OFF'}")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
