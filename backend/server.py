from fastapi import FastAPI, APIRouter, HTTPException, Depends, Body, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import requests
from pathlib import Path
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Optional, Any
from datetime import datetime
from bs4 import BeautifulSoup
import anthropic
import json

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Claude API client
def get_claude_client():
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        logging.warning("CLAUDE_API_KEY is not set in environment variables")
        return None
    return anthropic.Anthropic(api_key=api_key)

# Define Models
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

class WebsiteURL(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: HttpUrl
    title: str
    description: Optional[str] = None
    added_at: datetime = Field(default_factory=datetime.utcnow)
    last_scraped: Optional[datetime] = None
    content_cache: Optional[str] = None

class WebsiteURLCreate(BaseModel):
    url: HttpUrl
    title: str
    description: Optional[str] = None

class WebsiteURLUpdate(BaseModel):
    url: Optional[HttpUrl] = None
    title: Optional[str] = None
    description: Optional[str] = None

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    role: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Conversation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    messages: List[Message] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None

class ChatResponse(BaseModel):
    id: str
    response: str
    conversation_id: str

class ApiKeyConfig(BaseModel):
    claude_api_key: str

# Helper function to scrape webpage content
async def scrape_url(url: str) -> str:
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'lxml')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
        
        # Get text content
        text = soup.get_text(separator='\n')
        
        # Clean up text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        logging.error(f"Error scraping URL {url}: {str(e)}")
        return ""

# Add basic routes
@api_router.get("/")
async def root():
    return {"message": "Hello World"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Setup API key
@api_router.post("/config/api-key")
async def set_api_key(config: ApiKeyConfig):
    # Update .env file with API key
    try:
        env_path = ROOT_DIR / '.env'
        
        # Read existing content
        with open(env_path, 'r') as file:
            content = file.read()
        
        # Check if CLAUDE_API_KEY exists
        if "CLAUDE_API_KEY" in content:
            # Replace existing key
            lines = content.split('\n')
            updated_lines = []
            for line in lines:
                if line.startswith("CLAUDE_API_KEY="):
                    updated_lines.append(f"CLAUDE_API_KEY=\"{config.claude_api_key}\"")
                else:
                    updated_lines.append(line)
            
            updated_content = '\n'.join(updated_lines)
        else:
            # Add new key
            updated_content = content + f"\nCLAUDE_API_KEY=\"{config.claude_api_key}\"\n"
        
        # Write back to file
        with open(env_path, 'w') as file:
            file.write(updated_content)
        
        os.environ["CLAUDE_API_KEY"] = config.claude_api_key
        
        return {"status": "success", "message": "API key updated successfully"}
    
    except Exception as e:
        logging.error(f"Error setting API key: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error setting API key: {str(e)}")

# Website URL management
@api_router.post("/websites", response_model=WebsiteURL)
async def create_website(website: WebsiteURLCreate):
    website_dict = website.dict()
    website_obj = WebsiteURL(**website_dict)
    
    # Scrape content immediately
    content = await scrape_url(str(website_obj.url))
    website_obj.content_cache = content
    website_obj.last_scraped = datetime.utcnow()
    
    result = await db.websites.insert_one(website_obj.dict())
    return website_obj

@api_router.get("/websites", response_model=List[WebsiteURL])
async def get_websites():
    websites = await db.websites.find().to_list(1000)
    return [WebsiteURL(**website) for website in websites]

@api_router.get("/websites/{website_id}", response_model=WebsiteURL)
async def get_website(website_id: str):
    website = await db.websites.find_one({"id": website_id})
    if website:
        return WebsiteURL(**website)
    raise HTTPException(status_code=404, detail="Website not found")

@api_router.put("/websites/{website_id}", response_model=WebsiteURL)
async def update_website(website_id: str, website_update: WebsiteURLUpdate):
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    website_data = WebsiteURL(**website)
    
    # Update fields if provided
    update_data = website_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(website_data, field, value)
    
    # If URL changed, re-scrape content
    if "url" in update_data:
        content = await scrape_url(str(website_data.url))
        website_data.content_cache = content
        website_data.last_scraped = datetime.utcnow()
    
    await db.websites.update_one({"id": website_id}, {"$set": website_data.dict()})
    return website_data

@api_router.delete("/websites/{website_id}")
async def delete_website(website_id: str):
    result = await db.websites.delete_one({"id": website_id})
    if result.deleted_count:
        return {"status": "success", "message": "Website deleted"}
    raise HTTPException(status_code=404, detail="Website not found")

@api_router.post("/websites/{website_id}/refresh")
async def refresh_website_content(website_id: str):
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    website_data = WebsiteURL(**website)
    content = await scrape_url(str(website_data.url))
    website_data.content_cache = content
    website_data.last_scraped = datetime.utcnow()
    
    await db.websites.update_one({"id": website_id}, {"$set": website_data.dict()})
    return {"status": "success", "message": "Website content refreshed"}

# Chat functionality
@api_router.post("/chat", response_model=ChatResponse)
async def chat(chat_request: ChatRequest):
    client = get_claude_client()
    if not client:
        raise HTTPException(
            status_code=500, 
            detail="Claude API key not configured. Please set up the API key first."
        )
    
    # Get or create conversation
    conversation_id = chat_request.conversation_id
    if conversation_id:
        conversation = await db.conversations.find_one({"id": conversation_id})
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
        conversation = Conversation(**conversation)
    else:
        conversation = Conversation()
        await db.conversations.insert_one(conversation.dict())
    
    # Add user message to conversation
    user_message = Message(content=chat_request.message, role="user")
    conversation.messages.append(user_message)
    
    # Get all website content to provide context
    websites = await db.websites.find().to_list(1000)
    context = ""
    
    if websites:
        for website in websites:
            if website.get("content_cache"):
                context += f"\n\nContent from {website.get('title', 'Unknown')} ({website.get('url', 'No URL')}):\n"
                context += website.get("content_cache", "")
    
    # Prepare messages for Claude
    system_prompt = """You are a helpful AI assistant for a product information chatbot. 
    You have access to scraped content from product pages. 
    Use this information to answer user questions about products.
    Always be friendly, concise, and accurate.
    If you don't know the answer or can't find relevant information in the context, admit it instead of making up information.
    """
    
    # Extract conversation history
    messages = []
    for msg in conversation.messages[-10:]:  # Limit to last 10 messages
        messages.append({
            "role": msg.role,
            "content": msg.content
        })
    
    try:
        # Create the Claude API request
        response = client.messages.create(
            model="claude-3-opus-20240229",
            system=system_prompt,
            max_tokens=1024,
            messages=messages,
            context=context
        )
        
        # Extract the response
        ai_response = response.content[0].text
        
        # Add assistant message to conversation
        assistant_message = Message(content=ai_response, role="assistant")
        conversation.messages.append(assistant_message)
        conversation.updated_at = datetime.utcnow()
        
        # Update conversation in database
        await db.conversations.update_one(
            {"id": conversation.id},
            {"$set": {"messages": [msg.dict() for msg in conversation.messages], "updated_at": conversation.updated_at}}
        )
        
        return {
            "id": assistant_message.id,
            "response": ai_response,
            "conversation_id": conversation.id
        }
    
    except Exception as e:
        logging.error(f"Error calling Claude API: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error communicating with AI service: {str(e)}"
        )

# Get conversation history
@api_router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    conversation = await db.conversations.find_one({"id": conversation_id})
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation

# Include the router in the main app
app.include_router(api_router)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
