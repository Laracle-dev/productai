from fastapi import FastAPI, APIRouter, HTTPException, Depends, Body, Request, status, Response, Cookie, UploadFile, File, Form
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
import shutil
from pypdf import PdfReader
import io
import stripe

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

# Create collections for timeslots and bookings
timeslots_collection = db.timeslots
bookings_collection = db.bookings

# JWT Configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Admin credentials (simplified for demo)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "ryan@laracle.com")
ADMIN_PASSWORD = "admin123"  # Simplified for demo

# PDF Storage
PDF_DIR = ROOT_DIR / "pdf_storage"
PDF_DIR.mkdir(exist_ok=True)

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

class PdfDocument(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    path: str
    content_text: str
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)

class WebsiteURL(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    title: str
    description: Optional[str] = None
    added_at: datetime = Field(default_factory=datetime.utcnow)
    last_scraped: Optional[datetime] = None
    content_cache: Optional[str] = None
    pdfs: List[PdfDocument] = []

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
    calendly_url: Optional[str] = None
    has_custom_slots: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class TimeSlot(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    partner_id: str
    date: str
    start_time: str
    end_time: str
    price: float
    currency: str = "USD"
    available: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TimeSlotCreate(BaseModel):
    date: str
    start_time: str
    end_time: str
    price: float
    currency: str = "USD"

class ServicePartnerCreate(BaseModel):
    name: str
    service: str
    location: str
    email: EmailStr
    phone: str
    product_id: str
    calendly_url: Optional[str] = None
    has_custom_slots: bool = False

class ServicePartnerUpdate(BaseModel):
    name: Optional[str] = None
    service: Optional[str] = None
    location: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    product_id: Optional[str] = None
    calendly_url: Optional[str] = None
    has_custom_slots: Optional[bool] = None

class StripeConfig(BaseModel):
    publishable_key: str
    secret_key: str

class Booking(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timeslot_id: str
    partner_id: str
    payment_intent_id: str
    amount: float
    currency: str = "USD"
    customer_email: Optional[str] = None
    status: str = "pending"  # pending, confirmed, cancelled
    created_at: datetime = Field(default_factory=datetime.utcnow)

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
    """Send an email using Mailtrap SMTP server"""
    # Get Mailtrap credentials from environment variables
    smtp_host = os.environ.get("MAILTRAP_HOST", "smtp.mailtrap.io")
    smtp_port = int(os.environ.get("MAILTRAP_PORT", 2525))
    smtp_user = os.environ.get("MAILTRAP_USERNAME")
    smtp_pass = os.environ.get("MAILTRAP_PASSWORD")
    
    # If Mailtrap credentials are not available, fall back to existing credentials
    if not all([smtp_user, smtp_pass]):
        smtp_host = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
        smtp_port = int(os.environ.get("EMAIL_PORT", 587))
        smtp_user = os.environ.get("EMAIL_USER")
        smtp_pass = os.environ.get("EMAIL_PASSWORD")
        
        # If still no credentials, just log the email for development
        if not all([smtp_user, smtp_pass]):
            logging.info(f"Simulating email to {to_email}: Subject: {subject}, Body: {body}")
            return True
    
    # Create the email message
    message = MIMEMultipart()
    message["From"] = os.environ.get("MAILTRAP_FROM_EMAIL", "no-reply@ryansbrainai.com")
    message["To"] = to_email
    message["Subject"] = subject
    
    # Add body to email
    message.attach(MIMEText(body, "plain"))
    
    try:
        # Create a secure connection with the server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()  # Upgrade the connection to secure
        server.login(smtp_user, smtp_pass)
        
        # Send email
        server.sendmail(message["From"], to_email, message.as_string())
        server.quit()
        
        logging.info(f"Email sent to {to_email} via {smtp_host}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        # Fall back to logging the email for development purposes
        logging.info(f"[FALLBACK] Would have sent email to {to_email}: Subject: {subject}, Body: {body}")
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

# PDF Processing Functions
def extract_text_from_pdf(pdf_file):
    """Extract text content from a PDF file"""
    try:
        reader = PdfReader(pdf_file)
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        logging.error(f"Error extracting text from PDF: {str(e)}")
        return ""

# Authentication and Authorization
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logging.info(f"Decoding token: {token[:10]}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logging.info(f"Token payload: {payload}")
        email: str = payload.get("sub")
        if email is None:
            logging.error("No subject in token")
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError as e:
        logging.error(f"JWT error: {str(e)}")
        raise credentials_exception
    
    # For demo purposes, we'll accept any token with the admin email
    if token_data.email == ADMIN_EMAIL:
        logging.info(f"Admin user authenticated: {token_data.email}")
        return {"email": ADMIN_EMAIL, "is_admin": True, "is_active": True}
    
    logging.error(f"User not found: {token_data.email}")
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
    logging.info(f"Login attempt for email: {login_request.email}")
    
    # For demo purposes, only check against the hard-coded admin credentials
    if login_request.email != ADMIN_EMAIL or login_request.password != ADMIN_PASSWORD:
        logging.warning(f"Invalid credentials for email: {login_request.email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate a random 2FA code
    code = generate_2fa_code()
    
    # Store 2FA code in database
    current_time = datetime.utcnow()
    expiration = current_time + timedelta(minutes=10)
    
    await db.two_factor_codes.delete_many({"email": login_request.email})
    await db.two_factor_codes.insert_one({
        "email": login_request.email,
        "code": code,
        "expires_at": expiration
    })
    
    # Send 2FA code via email using Mailtrap
    email_body = f"""
    Your verification code for Ryan's Brain AI is: {code}
    
    This code will expire in 10 minutes.
    
    If you didn't request this code, please ignore this email.
    """
    
    send_email(
        login_request.email,
        "Your 2FA Code for Ryan's Brain AI",
        email_body
    )
    
    # Log the code for testing purposes (REMOVE IN PRODUCTION)
    logging.info(f"2FA code for {login_request.email}: {code}")
    
    # For demo, also indicate that 123456 works as a fallback code
    return {"message": "2FA code sent to your email. For demo purposes, you can also use '123456' as your verification code."}

@api_router.post("/verify-2fa")
async def verify_2fa(two_factor_request: TwoFactorRequest):
    logging.info(f"2FA verification attempt for email: {two_factor_request.email}, code: {two_factor_request.code}")
    
    # Find the 2FA code
    two_factor = await db.two_factor_codes.find_one({
        "email": two_factor_request.email,
        "code": two_factor_request.code,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    # For demo, also accept "123456" as a valid code
    if not two_factor and two_factor_request.code != "123456":
        logging.warning(f"Invalid or expired 2FA code for email: {two_factor_request.email}")
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")
    
    # Delete the used 2FA code if it exists
    if two_factor:
        await db.two_factor_codes.delete_one({"_id": two_factor["_id"]})
        logging.info(f"Valid 2FA code used and deleted for email: {two_factor_request.email}")
    else:
        logging.info(f"Using demo code 123456 for email: {two_factor_request.email}")
    
    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": two_factor_request.email},
        expires_delta=access_token_expires
    )
    
    logging.info(f"Access token generated for email: {two_factor_request.email}")
    
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

@api_router.delete("/config/api-key")
async def remove_api_key(current_user: dict = Depends(get_admin_user)):
    # Remove API key from .env file
    try:
        env_path = ROOT_DIR / '.env'
        
        # Read existing content
        with open(env_path, 'r') as file:
            content = file.read()
        
        # Check if CLAUDE_API_KEY exists
        if "CLAUDE_API_KEY" in content:
            # Remove the API key line
            lines = content.split('\n')
            updated_lines = []
            for line in lines:
                if not line.startswith("CLAUDE_API_KEY="):
                    updated_lines.append(line)
            
            updated_content = '\n'.join(updated_lines)
            
            # Write back to file
            with open(env_path, 'w') as file:
                file.write(updated_content)
            
            # Remove from environment variables
            if "CLAUDE_API_KEY" in os.environ:
                del os.environ["CLAUDE_API_KEY"]
            
            return {"status": "success", "message": "API key removed successfully"}
        else:
            return {"status": "success", "message": "No API key found to remove"}
    
    except Exception as e:
        logging.error(f"Error removing API key: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error removing API key: {str(e)}")

@api_router.get("/config/api-key/status")
async def check_api_key_status(current_user: dict = Depends(get_admin_user)):
    # Check if Claude API key is set
    api_key = os.environ.get("CLAUDE_API_KEY")
    return {"has_api_key": api_key is not None and api_key.strip() != ""}

# Stripe configuration endpoints
@api_router.post("/config/stripe")
async def set_stripe_config(config: StripeConfig, current_user: dict = Depends(get_admin_user)):
    try:
        env_path = ROOT_DIR / '.env'
        
        # Read existing content
        with open(env_path, 'r') as file:
            content = file.read()
        
        # Update or add Stripe keys
        lines = content.split('\n')
        updated_lines = []
        pub_key_added = False
        secret_key_added = False
        
        for line in lines:
            if line.startswith("STRIPE_PUBLISHABLE_KEY="):
                updated_lines.append(f'STRIPE_PUBLISHABLE_KEY="{config.publishable_key}"')
                pub_key_added = True
            elif line.startswith("STRIPE_SECRET_KEY="):
                updated_lines.append(f'STRIPE_SECRET_KEY="{config.secret_key}"')
                secret_key_added = True
            else:
                updated_lines.append(line)
        
        if not pub_key_added:
            updated_lines.append(f'STRIPE_PUBLISHABLE_KEY="{config.publishable_key}"')
        if not secret_key_added:
            updated_lines.append(f'STRIPE_SECRET_KEY="{config.secret_key}"')
        
        updated_content = '\n'.join(updated_lines)
        
        # Write back to file
        with open(env_path, 'w') as file:
            file.write(updated_content)
        
        # Update environment variables
        os.environ["STRIPE_PUBLISHABLE_KEY"] = config.publishable_key
        os.environ["STRIPE_SECRET_KEY"] = config.secret_key
        
        # Initialize Stripe with the secret key
        stripe.api_key = config.secret_key
        
        return {"status": "success", "message": "Stripe configuration updated successfully"}
    
    except Exception as e:
        logging.error(f"Error setting Stripe config: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error setting Stripe config: {str(e)}")

@api_router.get("/config/stripe")
async def get_stripe_config(current_user: dict = Depends(get_admin_user)):
    publishable_key = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    has_secret_key = bool(os.environ.get("STRIPE_SECRET_KEY", ""))
    
    return {
        "has_keys": bool(publishable_key and has_secret_key),
        "publishable_key": publishable_key
    }

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
    # First get the website to check if it has PDFs to delete
    website = await db.websites.find_one({"id": website_id})
    if website and "pdfs" in website:
        # Delete associated PDF files
        for pdf in website["pdfs"]:
            pdf_path = Path(pdf["path"])
            if pdf_path.exists():
                pdf_path.unlink()
    
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

# PDF Upload and Management
@api_router.post("/websites/{website_id}/pdfs")
async def upload_pdf(
    website_id: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_admin_user)
):
    # Verify the website exists
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    # Verify it's actually a PDF
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="File must be a PDF")
    
    # Create a unique filename
    safe_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = PDF_DIR / safe_filename
    
    try:
        # Read the file content
        contents = await file.read()
        
        # Save the file
        with open(file_path, "wb") as f:
            f.write(contents)
        
        # Extract text from the PDF
        pdf_text = extract_text_from_pdf(io.BytesIO(contents))
        
        # Create PDF document record
        pdf_doc = PdfDocument(
            filename=file.filename,
            path=str(file_path),
            content_text=pdf_text
        )
        
        # Update the website with the new PDF
        website_data = WebsiteURL(**website)
        if not hasattr(website_data, 'pdfs'):
            website_data.pdfs = []
        
        website_data.pdfs.append(pdf_doc)
        
        # Update in the database
        await db.websites.update_one(
            {"id": website_id},
            {"$set": {"pdfs": [pdf.dict() for pdf in website_data.pdfs]}}
        )
        
        return {"status": "success", "message": "PDF uploaded successfully", "pdf": pdf_doc.dict()}
    
    except Exception as e:
        # If there's an error, clean up any partially created file
        if file_path.exists():
            file_path.unlink()
        
        logging.error(f"Error uploading PDF: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error uploading PDF: {str(e)}")

@api_router.get("/websites/{website_id}/pdfs")
async def get_website_pdfs(website_id: str, current_user: dict = Depends(get_admin_user)):
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    if "pdfs" not in website or not website["pdfs"]:
        return []
    
    return website["pdfs"]

@api_router.delete("/websites/{website_id}/pdfs/{pdf_id}")
async def delete_pdf(website_id: str, pdf_id: str, current_user: dict = Depends(get_admin_user)):
    # Get the website
    website = await db.websites.find_one({"id": website_id})
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    # Find the PDF
    if "pdfs" not in website:
        raise HTTPException(status_code=404, detail="PDF not found")
    
    pdfs = website["pdfs"]
    pdf_to_delete = None
    remaining_pdfs = []
    
    for pdf in pdfs:
        if pdf["id"] == pdf_id:
            pdf_to_delete = pdf
        else:
            remaining_pdfs.append(pdf)
    
    if not pdf_to_delete:
        raise HTTPException(status_code=404, detail="PDF not found")
    
    # Delete the file
    try:
        pdf_path = Path(pdf_to_delete["path"])
        if pdf_path.exists():
            pdf_path.unlink()
    except Exception as e:
        logging.error(f"Error deleting PDF file: {str(e)}")
    
    # Update the website record
    await db.websites.update_one(
        {"id": website_id},
        {"$set": {"pdfs": remaining_pdfs}}
    )
    
    return {"status": "success", "message": "PDF deleted successfully"}

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
    relevant_product_ids = []
    
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
            # Get website content
            if website.get("content_cache"):
                # Limit each website content to about 1000 words
                content = website.get("content_cache", "")
                words = content.split()
                if len(words) > 1000:
                    content = " ".join(words[:1000]) + "..."
                
                context += f"\n\nContent from {website.get('title', 'Unknown')} ({website.get('url', 'No URL')}):\n"
                context += content
            
            # Get PDF content from this website
            if "pdfs" in website and website["pdfs"]:
                for pdf in website["pdfs"][:2]:  # Limit to 2 PDFs per website
                    pdf_content = pdf.get("content_text", "")
                    if pdf_content:
                        words = pdf_content.split()
                        if len(words) > 1000:
                            pdf_content = " ".join(words[:1000]) + "..."
                        
                        context += f"\n\nContent from PDF document '{pdf.get('filename', 'Unknown')}' for {website.get('title', 'Unknown')}:\n"
                        context += pdf_content
            
            # Store the product ID for service partner lookup
            relevant_product_ids.append(website.get("id"))
    
    # Check if service partners should be included
    service_keywords = ['service', 'repair', 'fix', 'help', 'support', 'maintenance', 'install', 'assistance']
    should_include_partners = any(keyword in chat_request.message.lower() for keyword in service_keywords)
    
    service_partner_info = ""
    if should_include_partners and relevant_product_ids:
        # Get service partners for the relevant products
        all_partners = []
        for product_id in relevant_product_ids:
            partners = await db.service_partners.find({"product_id": product_id}).to_list(100)
            if partners:
                all_partners.extend(partners)
        
        if all_partners:
            service_partner_info = "\n\nService Partners Information:\n"
            for partner in all_partners[:3]:  # Limit to 3 partners to save tokens
                service_partner_info += f"\nName: {partner.get('name')}\n"
                service_partner_info += f"Service: {partner.get('service')}\n"
                service_partner_info += f"Location: {partner.get('location')}\n"
                service_partner_info += f"Contact: {partner.get('email')} / {partner.get('phone')}\n"
    
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
    
    IMPORTANT: If the user asks about support, repairs, service, maintenance, installation, or help with their product, offer to connect them with a service partner.
    
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
        
        if service_partner_info:
            enhanced_system_prompt += f"\n\n{service_partner_info}\n\nIf the user is asking about repairs, support, or services, mention these service partners and offer to connect the user with them. Ask if they would like to contact one of these partners."
        
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

# Time slot management endpoints
@api_router.post("/service-partners/{partner_id}/timeslots", response_model=TimeSlot)
async def create_timeslot(partner_id: str, timeslot: TimeSlotCreate, current_user: dict = Depends(get_admin_user)):
    try:
        # First check if the partner exists
        partner = await db.service_partners.find_one({"id": partner_id})
        if not partner:
            raise HTTPException(status_code=404, detail="Service partner not found")
        
        # Create the time slot
        timeslot_dict = timeslot.dict()
        timeslot_dict["partner_id"] = partner_id
        timeslot_dict["id"] = str(uuid.uuid4())
        timeslot_dict["available"] = True
        timeslot_dict["created_at"] = datetime.utcnow()
        
        await timeslots_collection.insert_one(timeslot_dict)
        
        # Update partner to use custom slots if not already set
        if not partner.get("has_custom_slots"):
            await db.service_partners.update_one(
                {"id": partner_id},
                {"$set": {"has_custom_slots": True}}
            )
        
        return TimeSlot(**timeslot_dict)
    except Exception as e:
        logging.error(f"Error creating time slot: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating time slot: {str(e)}")

@api_router.get("/service-partners/{partner_id}/timeslots", response_model=List[TimeSlot])
async def get_partner_timeslots(partner_id: str):
    timeslots = await timeslots_collection.find({"partner_id": partner_id}).to_list(length=100)
    return [TimeSlot(**slot) for slot in timeslots]

@api_router.delete("/service-partners/{partner_id}/timeslots/{timeslot_id}")
async def delete_timeslot(partner_id: str, timeslot_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        result = await timeslots_collection.delete_one({"id": timeslot_id, "partner_id": partner_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Time slot not found")
        
        # Check if there are any timeslots left for this partner
        remaining_slots = await timeslots_collection.count_documents({"partner_id": partner_id})
        if remaining_slots == 0:
            # No more slots, update has_custom_slots to False
            await db.service_partners.update_one(
                {"id": partner_id},
                {"$set": {"has_custom_slots": False}}
            )
        
        return {"status": "success", "message": "Time slot deleted successfully"}
    except Exception as e:
        logging.error(f"Error deleting time slot: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting time slot: {str(e)}")

# Stripe payment endpoints
@api_router.post("/create-payment-intent")
async def create_payment_intent(data: dict = Body(...)):
    try:
        # Check if Stripe is configured
        stripe_secret_key = os.environ.get("STRIPE_SECRET_KEY")
        if not stripe_secret_key:
            raise HTTPException(status_code=500, detail="Stripe is not configured")
        
        stripe.api_key = stripe_secret_key
        
        # Verify the time slot
        timeslot_id = data.get("timeslot_id")
        if not timeslot_id:
            raise HTTPException(status_code=400, detail="Time slot ID is required")
        
        timeslot = await timeslots_collection.find_one({"id": timeslot_id, "available": True})
        if not timeslot:
            raise HTTPException(status_code=404, detail="Time slot not found or unavailable")
        
        # Get partner details
        partner = await db.service_partners.find_one({"id": timeslot["partner_id"]})
        if not partner:
            raise HTTPException(status_code=404, detail="Service partner not found")
        
        # Calculate amount in cents (Stripe uses cents)
        amount = int(timeslot["price"] * 100)
        currency = timeslot.get("currency", "USD").lower()
        
        # Create a PaymentIntent with the order amount and currency
        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
            automatic_payment_methods={"enabled": True},
            metadata={
                "timeslot_id": timeslot_id,
                "partner_id": partner["id"],
                "service": partner["service"],
                "date": timeslot["date"],
                "time": f"{timeslot['start_time']} - {timeslot['end_time']}"
            }
        )
        
        return {
            "clientSecret": payment_intent.client_secret,
            "amount": amount,
            "currency": currency.upper(),
            "partner": {
                "name": partner["name"],
                "service": partner["service"]
            },
            "timeslot": {
                "date": timeslot["date"],
                "time": f"{timeslot['start_time']} - {timeslot['end_time']}"
            }
        }
    except stripe.error.StripeError as e:
        logging.error(f"Stripe error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        logging.error(f"Error creating payment intent: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating payment intent: {str(e)}")

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    try:
        stripe_secret_key = os.environ.get("STRIPE_SECRET_KEY")
        if not stripe_secret_key:
            raise HTTPException(status_code=500, detail="Stripe is not configured")
        
        stripe.api_key = stripe_secret_key
        
        # Get the webhook secret from environment
        webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
        
        # Get the webhook data
        payload = await request.body()
        sig_header = request.headers.get("stripe-signature")
        
        # Verify webhook signature if secret is set
        event = None
        if webhook_secret:
            try:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, webhook_secret
                )
            except ValueError as e:
                # Invalid payload
                raise HTTPException(status_code=400, detail=str(e))
            except stripe.error.SignatureVerificationError as e:
                # Invalid signature
                raise HTTPException(status_code=400, detail=str(e))
        else:
            # No webhook secret, parse the payload directly
            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Handle the event
        if event["type"] == "payment_intent.succeeded":
            payment_intent = event["data"]["object"]
            
            # Mark the time slot as booked
            timeslot_id = payment_intent["metadata"].get("timeslot_id")
            if timeslot_id:
                await timeslots_collection.update_one(
                    {"id": timeslot_id},
                    {"$set": {"available": False}}
                )
                
                # Create a booking record
                booking = {
                    "id": str(uuid.uuid4()),
                    "timeslot_id": timeslot_id,
                    "partner_id": payment_intent["metadata"].get("partner_id"),
                    "payment_intent_id": payment_intent["id"],
                    "amount": payment_intent["amount"],
                    "currency": payment_intent["currency"],
                    "customer_email": payment_intent.get("receipt_email"),
                    "status": "confirmed",
                    "created_at": datetime.utcnow()
                }
                
                await bookings_collection.insert_one(booking)
        
        return {"status": "success"}
    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing webhook: {str(e)}")

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
