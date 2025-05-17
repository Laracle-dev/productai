from fastapi import FastAPI, APIRouter, HTTPException, Depends, Body, Request, status, Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import requests
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field, HttpUrl, EmailStr
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import anthropic
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from jose import JWTError, jwt
from passlib.context import CryptContext
import time
import secrets

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'test_database')]

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# JWT Configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Admin credentials (simplified for demo)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "ryan@laracle.com")
ADMIN_PASSWORD = "admin123"  # Simplified for demo

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

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
    url: str
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
    url: Optional[str] = None
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

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class ServicePartner(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    service: str
    location: str
    email: EmailStr
    phone: str
    product_id: str  # ID of the associated product/website
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ServicePartnerCreate(BaseModel):
    name: str
    service: str
    location: str
    email: EmailStr
    phone: str
    product_id: str

class ServicePartnerUpdate(BaseModel):
    name: Optional[str] = None
    service: Optional[str] = None
    location: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    product_id: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    is_active: bool = True
    is_admin: bool = False

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TwoFactorRequest(BaseModel):
    email: EmailStr
    code: str

# Email and 2FA functions
def send_email(to_email: str, subject: str, body: str):
    """Simulate sending an email (for demo purposes)"""
    logging.info(f"Simulating email to {to_email}: Subject: {subject}, Body: {body}")
    return True

def generate_2fa_code():
    """Generate a 6-digit 2FA code"""
    return ''.join(random.choices(string.digits, k=6))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Authentication and Authorization
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    # For demo purposes, we'll accept any token with the admin email
    if token_data.email == ADMIN_EMAIL:
        return {"email": ADMIN_EMAIL, "is_admin": True, "is_active": True}
    
    raise credentials_exception

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.get("is_active", False):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_admin_user(current_user: dict = Depends(get_current_active_user)):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource"
        )
    return current_user

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

# Authentication Routes
@api_router.post("/login")
async def login(login_request: LoginRequest):
    # For demo purposes, only check against the hard-coded admin credentials
    if login_request.email != ADMIN_EMAIL or login_request.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate and store 2FA code
    code = "123456"  # Fixed code for demo
    
    # Simulate storing the code
    current_time = datetime.utcnow()
    expiration = current_time + timedelta(minutes=10)
    
    # Store 2FA code in database
    await db.two_factor_codes.delete_many({"email": login_request.email})
    await db.two_factor_codes.insert_one({
        "email": login_request.email,
        "code": code,
        "expires_at": expiration
    })
    
    # Simulate sending 2FA code via email
    email_body = f"Your verification code is: {code}\nThis code will expire in 10 minutes."
    send_email(
        login_request.email,
        "Your 2FA Code for Product AI Chatbot",
        email_body
    )
    
    # Log the code for testing purposes (REMOVE IN PRODUCTION)
    logging.info(f"2FA code for {login_request.email}: {code}")
    
    return {"message": "2FA code sent to your email (check server logs for code)"}

@api_router.post("/verify-2fa")
async def verify_2fa(two_factor_request: TwoFactorRequest):
    # Find the 2FA code
    two_factor = await db.two_factor_codes.find_one({
        "email": two_factor_request.email,
        "code": two_factor_request.code,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    # For demo, also accept "123456" as a valid code
    if not two_factor and two_factor_request.code != "123456":
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")
    
    # Delete the used 2FA code if it exists
    if two_factor:
        await db.two_factor_codes.delete_one({"_id": two_factor["_id"]})
    
    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": two_factor_request.email},
        expires_delta=access_token_expires
    )
    
    # Return token
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/logout")
async def logout(current_user: dict = Depends(get_current_active_user)):
    # In a stateless JWT system, we can't invalidate tokens on the server
    # The client needs to discard the token
    return {"message": "Successfully logged out"}

# Setup API key - Now requires admin authentication
@api_router.post("/config/api-key")
async def set_api_key(config: ApiKeyConfig, current_user: dict = Depends(get_admin_user)):
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

# Website URL management - Now requires admin authentication
@api_router.post("/websites", response_model=WebsiteURL)
async def create_website(website: WebsiteURLCreate, current_user: dict = Depends(get_admin_user)):
    website_dict = website.dict()
    # Convert HttpUrl to string to avoid MongoDB serialization issues
    website_dict["url"] = str(website_dict["url"])
    website_obj = WebsiteURL(**website_dict)
    
    # Scrape content immediately
    content = await scrape_url(str(website_obj.url))
    website_obj.content_cache = content
    website_obj.last_scraped = datetime.utcnow()
    
    result = await db.websites.insert_one(website_obj.dict())
    return website_obj

@api_router.get("/websites", response_model=List[WebsiteURL])
async def get_websites(current_user: dict = Depends(get_admin_user)):
    websites = await db.websites.find().to_list(1000)
    return [WebsiteURL(**website) for website in websites]

@api_router.get("/websites/{website_id}", response_model=WebsiteURL)
async def get_website(website_id: str, current_user: dict = Depends(get_admin_user)):
    website = await db.websites.find_one({"id": website_id})
    if website:
        return WebsiteURL(**website)
    raise HTTPException(status_code=404, detail="Website not found")

@api_router.put("/websites/{website_id}", response_model=WebsiteURL)
async def update_website(website_id: str, website_update: WebsiteURLUpdate, current_user: dict = Depends(get_admin_user)):
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    website_data = WebsiteURL(**website)
    
    # Update fields if provided
    update_data = website_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        # Convert HttpUrl to string if present
        if field == "url" and value:
            setattr(website_data, field, str(value))
        else:
            setattr(website_data, field, value)
    
    # If URL changed, re-scrape content
    if "url" in update_data:
        content = await scrape_url(str(website_data.url))
        website_data.content_cache = content
        website_data.last_scraped = datetime.utcnow()
    
    await db.websites.update_one({"id": website_id}, {"$set": website_data.dict()})
    return website_data

@api_router.delete("/websites/{website_id}")
async def delete_website(website_id: str, current_user: dict = Depends(get_admin_user)):
    result = await db.websites.delete_one({"id": website_id})
    if result.deleted_count:
        return {"status": "success", "message": "Website deleted"}
    raise HTTPException(status_code=404, detail="Website not found")

@api_router.post("/websites/{website_id}/refresh")
async def refresh_website_content(website_id: str, current_user: dict = Depends(get_admin_user)):
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    website_data = WebsiteURL(**website)
    content = await scrape_url(str(website_data.url))
    website_data.content_cache = content
    website_data.last_scraped = datetime.utcnow()
    
    await db.websites.update_one({"id": website_id}, {"$set": website_data.dict()})
    return {"status": "success", "message": "Website content refreshed"}

# Chat functionality - No authentication required for regular users
@api_router.post("/chat", response_model=ChatResponse)
async def chat(chat_request: ChatRequest):
    # Add a small delay to avoid hitting Claude's rate limits
    await asyncio.sleep(1)
    
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
        # First pass - find the website most relevant to the question
        user_question = chat_request.message.lower()
        
        # Sort websites by potential relevance (simple keyword matching)
        sorted_websites = sorted(
            websites,
            key=lambda w: sum(1 for word in user_question.split() 
                              if word in w.get("title", "").lower() 
                              or word in w.get("description", "").lower()),
            reverse=True
        )
        
        # Only use the top 2 most relevant websites to limit context size
        for website in sorted_websites[:2]:
            if website.get("content_cache"):
                # Limit each website content to about 1000 words
                content = website.get("content_cache", "")
                words = content.split()
                if len(words) > 1000:
                    content = " ".join(words[:1000]) + "..."
                
                context += f"\n\nContent from {website.get('title', 'Unknown')} ({website.get('url', 'No URL')}):\n"
                context += content
    
    # Prepare messages for Claude
    system_prompt = """You are a helpful AI assistant for a product information chatbot. 
    
    RESPONSE GUIDELINES:
    1. Keep your responses brief and concise (under 150 words)
    2. Use formatting to organize information:
       - Use bullet points for lists
       - Use bold for important features or specifications
       - Use headings to separate sections when appropriate
    3. Focus on the most relevant information only
    4. If comparing products, use a clear structure
    5. Highlight pricing, key features, and specifications clearly
    
    When answering about products, be friendly but direct. Prioritize the most important information the user is likely looking for.
    
    If you don't know the answer or can't find relevant information in the provided context, briefly admit it instead of making up information.
    """
    
    # Extract conversation history - limit to last 3 messages to save tokens
    messages = []
    for msg in conversation.messages[-3:]:  # Limit to last 3 messages
        messages.append({
            "role": msg.role,
            "content": msg.content
        })
    
    try:
        # Create the Claude API request
        # Combine system prompt with context
        enhanced_system_prompt = system_prompt
        if context:
            enhanced_system_prompt += f"\n\nHere is information about our products that you can use to answer questions:\n{context}"
        
        response = client.messages.create(
            model="claude-3-opus-20240229",
            system=enhanced_system_prompt,
            max_tokens=1024,
            messages=messages
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

# Authentication check endpoint
@api_router.get("/auth/check")
async def check_auth(current_user: dict = Depends(get_current_active_user)):
    return {
        "authenticated": True,
        "email": current_user.get("email"),
        "is_admin": current_user.get("is_admin", False)
    }

# Service Partner Management
@api_router.post("/service-partners", response_model=ServicePartner)
async def create_service_partner(partner: ServicePartnerCreate, current_user: dict = Depends(get_admin_user)):
    # First check if the product exists
    website = await db.websites.find_one({"id": partner.product_id})
    if not website:
        raise HTTPException(status_code=404, detail="Product not found")
    
    partner_dict = partner.dict()
    partner_obj = ServicePartner(**partner_dict)
    
    result = await db.service_partners.insert_one(partner_obj.dict())
    return partner_obj

@api_router.get("/service-partners", response_model=List[ServicePartner])
async def get_service_partners(current_user: dict = Depends(get_admin_user)):
    partners = await db.service_partners.find().to_list(1000)
    return [ServicePartner(**partner) for partner in partners]

@api_router.get("/service-partners/{partner_id}", response_model=ServicePartner)
async def get_service_partner(partner_id: str, current_user: dict = Depends(get_admin_user)):
    partner = await db.service_partners.find_one({"id": partner_id})
    if partner:
        return ServicePartner(**partner)
    raise HTTPException(status_code=404, detail="Service partner not found")

@api_router.put("/service-partners/{partner_id}", response_model=ServicePartner)
async def update_service_partner(partner_id: str, partner_update: ServicePartnerUpdate, current_user: dict = Depends(get_admin_user)):
    partner = await db.service_partners.find_one({"id": partner_id})
    if not partner:
        raise HTTPException(status_code=404, detail="Service partner not found")
    
    # If product_id is being updated, check if the new product exists
    if partner_update.product_id:
        website = await db.websites.find_one({"id": partner_update.product_id})
        if not website:
            raise HTTPException(status_code=404, detail="Product not found")
    
    partner_data = ServicePartner(**partner)
    
    # Update fields if provided
    update_data = partner_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(partner_data, field, value)
    
    partner_data.updated_at = datetime.utcnow()
    
    await db.service_partners.update_one({"id": partner_id}, {"$set": partner_data.dict()})
    return partner_data

@api_router.delete("/service-partners/{partner_id}")
async def delete_service_partner(partner_id: str, current_user: dict = Depends(get_admin_user)):
    result = await db.service_partners.delete_one({"id": partner_id})
    if result.deleted_count:
        return {"status": "success", "message": "Service partner deleted"}
    raise HTTPException(status_code=404, detail="Service partner not found")

@api_router.get("/websites/{website_id}/service-partners", response_model=List[ServicePartner])
async def get_service_partners_by_product(website_id: str):
    partners = await db.service_partners.find({"product_id": website_id}).to_list(1000)
    return [ServicePartner(**partner) for partner in partners]

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
