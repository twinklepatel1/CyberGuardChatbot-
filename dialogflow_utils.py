"""
Dialogflow Helper Functions
Created by Twinkle Patel

This was my first time working with Dialogflow API!
Spent way too long figuring out the authentication 😅
"""

import json
import os
import logging
from typing import Dict, Any, Optional

# Set up logging
logger = logging.getLogger(__name__)

# Try to import Google libraries - they can be finicky
try:
    from google.cloud import dialogflow_v2 as dialogflow
    from google.api_core.exceptions import InvalidArgument, PermissionDenied
    GOOGLE_AVAILABLE = True
except ImportError:
    logger.warning("⚠️ Google Cloud libraries not installed. Dialogflow features disabled.")
    GOOGLE_AVAILABLE = False

def detect_intent(project_id: str, session_id: str, text: str, 
                  language_code: str = 'en-US') -> Dict[str, Any]:
    """
    Send text to Dialogflow and get back the intent and response
    
    Args:
        project_id: Your GCP project ID
        session_id: Unique session identifier
        text: User's message
        language_code: Language (only English works for now)
    
    Returns:
        Dictionary with intent info and response text
    """
    
    # If Google libraries aren't available, return a fallback
    if not GOOGLE_AVAILABLE:
        logger.info("Using fallback response (Google Cloud not configured)")
        return {
            'fulfillment_text': None,
            'intent': 'fallback',
            'confidence': 0.0,
            'parameters': {}
        }
    
    try:
        # Create a session client
        session_client = dialogflow.SessionsClient()
        session = session_client.session_path(project_id, session_id)
        
        logger.debug(f"Session path: {session}")
        
        # Prepare the text input
        text_input = dialogflow.types.TextInput(
            text=text, 
            language_code=language_code
        )
        
        query_input = dialogflow.types.QueryInput(text=text_input)
        
        # Send to Dialogflow (with timeout so we don't hang forever)
        response = session_client.detect_intent(
            session=session, 
            query_input=query_input,
            timeout=10  # 10 second timeout
        )
        
        # Extract parameters (this took me a while to figure out)
        parameters = {}
        if response.query_result.parameters:
            for key, value in response.query_result.parameters.items():
                # Handle different value types
                if hasattr(value, 'string_value'):
                    parameters[key] = value.string_value
                elif hasattr(value, 'number_value'):
                    parameters[key] = value.number_value
                elif hasattr(value, 'bool_value'):
                    parameters[key] = value.bool_value
                else:
                    parameters[key] = str(value)
        
        intent_name = response.query_result.intent.display_name if response.query_result.intent else 'unknown'
        confidence = response.query_result.intent_detection_confidence
        
        logger.info(f"🤖 Intent: {intent_name} (confidence: {confidence:.2f})")
        
        return {
            'fulfillment_text': response.query_result.fulfillment_text,
            'intent': intent_name,
            'confidence': confidence,
            'parameters': parameters
        }
        
    except PermissionDenied:
        logger.error("🔑 Permission denied! Check your Google Cloud credentials.")
        return {
            'fulfillment_text': "I'm having authentication issues. Please check API credentials.",
            'intent': 'error',
            'confidence': 0,
            'parameters': {}
        }
    except InvalidArgument as e:
        logger.error(f"❌ Invalid argument: {e}")
        return {
            'fulfillment_text': "I couldn't understand that query. Could you rephrase?",
            'intent': 'error',
            'confidence': 0,
            'parameters': {}
        }
    except Exception as e:
        logger.error(f"🔥 Unexpected Dialogflow error: {e}")
        return {
            'fulfillment_text': None,
            'intent': 'fallback',
            'confidence': 0,
            'parameters': {}
        }

def create_session_id(user_id: Optional[str] = None) -> str:
    """
    Create a unique session ID for each user
    If user_id is provided, use that to maintain consistent sessions
    """
    import hashlib
    import time
    
    if user_id:
        # Create deterministic session ID from user_id
        hash_obj = hashlib.md5(user_id.encode())
        return f"user_{hash_obj.hexdigest()[:16]}"
    else:
        # Create random session ID with timestamp
        timestamp = int(time.time() * 1000)
        return f"session_{timestamp}_{os.urandom(4).hex()}"

# Quick test function I used while developing
if __name__ == "__main__":
    # Test the session ID generator
    print(f"Random session: {create_session_id()}")
    print(f"User session: {create_session_id('twinkle@example.com')}")
