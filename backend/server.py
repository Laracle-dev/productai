from fastapi import FastAPI, APIRouter, HTTPException, Depends, Body, Request, status, Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import requests
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

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

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
    """Send an email using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = os.environ.get("EMAIL_USER")
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(
            os.environ.get("EMAIL_HOST", "smtp.gmail.com"),
            int(os.environ.get("EMAIL_PORT", 587))
        )
        server.starttls()
        server.login(
            os.environ.get("EMAIL_USER"),
            os.environ.get("EMAIL_PASSWORD")
        )
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

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
    
    user = await db.users.find_one({"email": token_data.email})
    if user is None:
        raise credentials_exception
    return user

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

# Initialize admin user
@app.on_event("startup")
async def create_admin_user():
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    
    # Check if admin user already exists
    existing_admin = await db.users.find_one({"email": admin_email})
    if not existing_admin:
        # Create admin user
        admin_user = {
            "id": str(uuid.uuid4()),
            "email": admin_email,
            "hashed_password": admin_password_hash,
            "is_active": True,
            "is_admin": True,
            "created_at": datetime.utcnow()
        }
        await db.users.insert_one(admin_user)
        logging.info(f"Admin user created: {admin_email}")
    else:
        logging.info(f"Admin user already exists: {admin_email}")

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
    # Find user
    user = await db.users.find_one({"email": login_request.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not pwd_context.verify(login_request.password, user.get("hashed_password")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate and store 2FA code
    code = generate_2fa_code()
    
    # Save 2FA code and expiration time (10 minutes from now)
    expiration = datetime.utcnow() + timedelta(minutes=10)
    await db.two_factor_codes.insert_one({
        "email": login_request.email,
        "code": code,
        "expires_at": expiration
    })
    
    # Send 2FA code via email
    email_sent = send_email(
        login_request.email,
        "Your 2FA Code for Product AI Chatbot",
        f"Your verification code is: {code}\nThis code will expire in 10 minutes."
    )
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send 2FA code")
    
    return {"message": "2FA code sent to your email"}

@api_router.post("/verify-2fa")
async def verify_2fa(two_factor_request: TwoFactorRequest):
    # Find the 2FA code
    two_factor = await db.two_factor_codes.find_one({
        "email": two_factor_request.email,
        "code": two_factor_request.code,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not two_factor:
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")
    
    # Delete the used 2FA code
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

# Authentication check endpoint
@api_router.get("/auth/check")
async def check_auth(current_user: dict = Depends(get_current_active_user)):
    return {
        "authenticated": True,
        "email": current_user.get("email"),
        "is_admin": current_user.get("is_admin", False)
    }

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
