import { useState, useEffect, useRef, createContext, useContext } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import { Toaster, toast } from 'react-hot-toast';
import ReactMarkdown from 'react-markdown';
import "./App.css";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // Check if user is authenticated on mount
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      checkAuthStatus(token);
    } else {
      setLoading(false);
    }
  }, []);
  
  const checkAuthStatus = async (token) => {
    try {
      const response = await axios.get(`${API}/auth/check`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUser({
        email: response.data.email,
        isAdmin: response.data.is_admin,
        token
      });
    } catch (error) {
      // Token is invalid or expired
      console.error('Auth check failed:', error);
      localStorage.removeItem('token');
      setUser(null);
    } finally {
      setLoading(false);
    }
  };
  
  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/login`, { email, password });
      console.log('Login response:', response.data);
      return { success: true, needsVerification: true };
    } catch (error) {
      console.error('Login error:', error);
      throw new Error(error.response?.data?.detail || 'Login failed');
    }
  };
  
  const verify2FA = async (email, code) => {
    try {
      console.log('Verifying 2FA:', { email, code });
      const response = await axios.post(`${API}/verify-2fa`, { email, code });
      console.log('2FA response:', response.data);
      
      if (response.data && response.data.access_token) {
        const { access_token } = response.data;
        localStorage.setItem('token', access_token);
        await checkAuthStatus(access_token);
        return { success: true };
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('2FA verification error:', error);
      throw new Error(error.response?.data?.detail || 'Verification failed');
    }
  };
  
  const logout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await axios.post(`${API}/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` }
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('token');
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, verify2FA, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  if (!user.isAdmin) {
    return <Navigate to="/unauthorized" replace />;
  }
  
  return children;
};

// Energy Sphere Component
const EnergySphere = ({ isAnimating = true }) => {
  return (
    <div className="energy-sphere-container">
      <div className="energy-sphere" style={{ opacity: isAnimating ? 1 : 0.5, animation: !isAnimating ? 'none' : undefined }}>
        <div className="energy-sphere-ring"></div>
        <div className="energy-sphere-ring"></div>
        <div className="energy-sphere-ring"></div>
        <div className="energy-sphere-particles">
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
          <div className="energy-particle"></div>
        </div>
      </div>
    </div>
  );
};

// Chat Message Component
const ChatMessage = ({ message, isUser }) => {
  return (
    <div className={`my-4 ${isUser ? 'text-right' : 'text-left'}`}>
      <div
        className={`inline-block max-w-[80%] rounded-lg px-4 py-2 ${
          isUser
            ? 'bg-blue-600 text-white'
            : 'bg-gray-800 text-white message-content'
        }`}
      >
        {isUser ? (
          message
        ) : (
          <div className="markdown-content">
            <ReactMarkdown>{message}</ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  );
};

// Question Chip Component
const QuestionChip = ({ icon, question, onClick }) => {
  return (
    <div className="question-chip" onClick={onClick}>
      <span className="question-chip-icon">{icon}</span>
      <span>{question}</span>
    </div>
  );
};

// Login Component
const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [showVerification, setShowVerification] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login, verify2FA, user } = useAuth();
  
  // Redirect if already logged in
  useEffect(() => {
    if (user) {
      navigate('/admin');
    }
  }, [user, navigate]);
  
  const handleLogin = async (e) => {
    e.preventDefault();
    
    if (!email || !password) {
      toast.error('Email and password are required');
      return;
    }
    
    setLoading(true);
    
    try {
      console.log('Attempting login with:', { email });
      const result = await login(email, password);
      console.log('Login result:', result);
      if (result.needsVerification) {
        setShowVerification(true);
        toast.success('Please check your email for a verification code');
      }
    } catch (error) {
      console.error('Login form error:', error);
      toast.error(error.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };
  
  const handleVerify = async (e) => {
    e.preventDefault();
    
    if (!code) {
      toast.error('Verification code is required');
      return;
    }
    
    setLoading(true);
    
    try {
      console.log('Attempting verification with:', { email, code });
      const result = await verify2FA(email, code);
      console.log('Verification result:', result);
      if (result.success) {
        toast.success('Login successful');
        navigate('/admin');
      }
    } catch (error) {
      console.error('Verification form error:', error);
      toast.error(error.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="login-container">
      <h2 className="text-2xl font-bold mb-6 text-center">
        {showVerification ? 'Verify 2FA Code' : 'Admin Login'}
      </h2>
      
      {!showVerification ? (
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="login-input"
              placeholder="admin@example.com"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="login-input"
              placeholder="••••••••"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="login-button mt-4"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerify} className="space-y-4">
          <p className="text-gray-300 mb-4">
            A verification code has been sent to your email. Please enter it below.
          </p>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Verification Code
            </label>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="login-input"
              placeholder="123456"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="login-button"
          >
            {loading ? 'Verifying...' : 'Verify Code'}
          </button>
          <button
            type="button"
            onClick={() => setShowVerification(false)}
            className="w-full bg-gray-700 text-white py-2 px-4 rounded-md hover:bg-gray-600 mt-2"
          >
            Back to Login
          </button>
        </form>
      )}
    </div>
  );
};

// Unauthorized Page
const Unauthorized = () => {
  return (
    <div className="max-w-lg mx-auto mt-20 p-6 bg-gray-800 rounded-lg shadow-lg text-center">
      <h2 className="text-2xl font-bold mb-4 text-red-400">Access Denied</h2>
      <p className="text-gray-300 mb-6">
        You don't have permission to access this page. Please contact an administrator.
      </p>
      <a 
        href="/"
        className="inline-block bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        Go to Home
      </a>
    </div>
  );
};

// User Interface - Chat Component
const Chat = () => {
  const [message, setMessage] = useState('');
  const [conversation, setConversation] = useState([]);
  const [conversationId, setConversationId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showParticle, setShowParticle] = useState(true);
  const chatContainerRef = useRef(null);
  
  // Example questions
  const exampleQuestions = [
    { icon: "🔧", question: "Where can I get my product repaired?" },
    { icon: "🔎", question: "What are the key features of your product?" },
    { icon: "📦", question: "Do you provide installation services?" }
  ];
  
  // Scroll to bottom of chat when conversation updates
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [conversation]);

  // Hide the particle animation after first message
  useEffect(() => {
    if (conversation.length > 0) {
      setShowParticle(false);
    } else {
      setShowParticle(true);
    }
  }, [conversation]);

  const handleSendMessage = async (e) => {
    e?.preventDefault();
    
    if (!message.trim()) return;
    
    // Add user message to conversation
    setConversation(prev => [...prev, { content: message, role: 'user' }]);
    
    // Clear input field
    const sentMessage = message;
    setMessage('');
    
    // Set loading state
    setLoading(true);
    
    try {
      const response = await axios.post(`${API}/chat`, {
        message: sentMessage,
        conversation_id: conversationId
      });
      
      // Save conversation ID for subsequent messages
      if (!conversationId) {
        setConversationId(response.data.conversation_id);
      }
      
      // Add AI response to conversation
      setConversation(prev => [...prev, { 
        content: response.data.response, 
        role: 'assistant'
      }]);
    } catch (error) {
      console.error('Error sending message:', error);
      toast.error(error.response?.data?.detail || 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };

  const handleQuestionClick = (question) => {
    setMessage(question);
    setTimeout(() => {
      handleSendMessage();
    }, 100);
  };

  return (
    <div className="flex flex-col h-full max-w-2xl mx-auto">
      <div className="text-center pt-8 pb-2">
        <h1 className="text-3xl font-bold mb-1">ASK PRODUCT AI</h1>
        <p className="text-sm text-gray-400">Powered by Ryan's Brain</p>
      </div>
      
      {showParticle && conversation.length === 0 && (
        <div className="flex-1 flex flex-col items-center justify-center py-8">
          <EnergySphere isAnimating={true} />
          <p className="mt-6 text-gray-400 text-center max-w-sm">
            Powered by Ryan's Brain - making AI personal
            <br />
            Read more about our <span className="underline">data philosophy</span> ❤️
          </p>
        </div>
      )}
      
      {/* Chat messages container */}
      {(!showParticle || conversation.length > 0) && (
        <div 
          ref={chatContainerRef}
          className="flex-1 p-4 overflow-y-auto"
          style={{ maxHeight: 'calc(100vh - 280px)' }}
        >
          {conversation.map((msg, index) => (
            msg.role === 'user' ? (
              <ChatMessage 
                key={index} 
                message={msg.content} 
                isUser={true} 
              />
            ) : (
              <ChatMessage
                key={index}
                message={msg.content}
                isUser={false}
              />
            )
          ))}
          
          {/* Loading animation */}
          {loading && (
            <div className="my-4 text-left">
              <div className="inline-block bg-gray-800 text-white rounded-lg px-4 py-2">
                <motion.span
                  className="inline-block"
                  animate={{
                    opacity: [0, 1, 0]
                  }}
                  transition={{
                    duration: 1.2,
                    repeat: Infinity,
                    repeatType: "loop"
                  }}
                >
                  Thinking...
                </motion.span>
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Example questions */}
      {conversation.length === 0 && (
        <div className="px-4 py-2">
          <div className="flex flex-wrap -mx-2">
            {exampleQuestions.map((q, index) => (
              <div key={index} className="w-full md:w-1/2 lg:w-1/3 px-2 mb-2">
                <QuestionChip 
                  icon={q.icon} 
                  question={q.question} 
                  onClick={() => handleQuestionClick(q.question)}
                />
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Message input form */}
      <div className="p-4 mt-auto">
        <form onSubmit={handleSendMessage} className="relative">
          <input
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Ask about products, services, or repairs..."
            className="search-input w-full pr-12"
            disabled={loading}
          />
          <button
            type="submit"
            className="send-button absolute right-2 top-1/2 transform -translate-y-1/2"
            disabled={loading || !message.trim()}
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M18.3334 1.66666L9.16669 10.8333" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M18.3334 1.66666L12.5 18.3333L9.16669 10.8333L1.66669 7.49999L18.3334 1.66666Z" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </form>
      </div>
    </div>
  );
};

// PDF List Component
const PDFList = ({ productId, getAuthHeader, onRefresh }) => {
  const [pdfs, setPDFs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPDFs();
  }, [productId]);

  const fetchPDFs = async () => {
    try {
      const response = await axios.get(`${API}/websites/${productId}/pdfs`, getAuthHeader());
      setPDFs(response.data || []);
    } catch (error) {
      console.error('Error fetching PDFs:', error);
      toast.error('Failed to load PDFs');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (pdfId) => {
    if (!window.confirm('Are you sure you want to delete this PDF?')) {
      return;
    }
    
    try {
      await axios.delete(`${API}/websites/${productId}/pdfs/${pdfId}`, getAuthHeader());
      toast.success('PDF deleted successfully');
      fetchPDFs();
      if (onRefresh) onRefresh();
    } catch (error) {
      console.error('Error deleting PDF:', error);
      toast.error('Failed to delete PDF');
    }
  };

  if (loading) {
    return <div className="text-center py-4">Loading PDFs...</div>;
  }

  if (!pdfs || pdfs.length === 0) {
    return <div className="text-gray-400 py-2">No PDFs uploaded yet</div>;
  }

  return (
    <div className="space-y-2 mt-2">
      <h4 className="font-medium text-gray-300">Uploaded PDFs</h4>
      <div className="space-y-2">
        {pdfs.map(pdf => (
          <div key={pdf.id} className="flex justify-between items-center bg-gray-700 rounded p-2">
            <div className="flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-red-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
              </svg>
              <span className="text-sm truncate" title={pdf.filename}>{pdf.filename}</span>
            </div>
            <button
              onClick={() => handleDelete(pdf.id)}
              className="text-red-400 hover:text-red-300 p-1"
              title="Delete PDF"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

// PDF Upload Component
const PDFUploader = ({ productId, getAuthHeader, onUploadComplete }) => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.type === 'application/pdf') {
      setFile(selectedFile);
    } else {
      toast.error('Please select a valid PDF file');
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleUpload = async () => {
    if (!file) {
      toast.error('Please select a PDF file first');
      return;
    }

    setUploading(true);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      await axios.post(
        `${API}/websites/${productId}/pdfs`,
        formData,
        {
          ...getAuthHeader(),
          headers: {
            ...getAuthHeader().headers,
            'Content-Type': 'multipart/form-data'
          }
        }
      );
      
      toast.success('PDF uploaded successfully');
      setFile(null);
      
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
      if (onUploadComplete) {
        onUploadComplete();
      }
    } catch (error) {
      console.error('Error uploading PDF:', error);
      toast.error(error.response?.data?.detail || 'Failed to upload PDF');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="mt-4 p-3 border border-gray-700 rounded-md">
      <h4 className="font-medium text-white mb-2">Upload PDF Document</h4>
      <div className="flex flex-col space-y-3">
        <input
          type="file"
          accept=".pdf"
          onChange={handleFileChange}
          className="text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-gray-700 file:text-white hover:file:bg-gray-600"
          ref={fileInputRef}
          disabled={uploading}
        />
        {file && (
          <div className="text-sm text-gray-300">
            Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
          </div>
        )}
        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className={`px-4 py-2 rounded-md text-white ${!file || uploading ? 'bg-gray-600 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
        >
          {uploading ? 'Uploading...' : 'Upload PDF'}
        </button>
      </div>
    </div>
  );
};

// Service Partner List Component
const ServicePartnerList = ({ productId, onEdit, onDelete, getAuthHeader }) => {
  const [partners, setPartners] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedPartnerId, setExpandedPartnerId] = useState(null);
  const [showTimeSlots, setShowTimeSlots] = useState(false);

  useEffect(() => {
    fetchPartners();
  }, [productId]);

  const fetchPartners = async () => {
    try {
      const url = productId 
        ? `${API}/websites/${productId}/service-partners` 
        : `${API}/service-partners`;
      
      const response = await axios.get(url, getAuthHeader());
      setPartners(response.data);
    } catch (error) {
      console.error('Error fetching service partners:', error);
      toast.error('Failed to load service partners');
    } finally {
      setLoading(false);
    }
  };

  const togglePartnerExpansion = (partnerId) => {
    if (expandedPartnerId === partnerId) {
      setExpandedPartnerId(null);
      setShowTimeSlots(false);
    } else {
      setExpandedPartnerId(partnerId);
      setShowTimeSlots(false);
    }
  };

  if (loading) {
    return <div className="text-center py-4">Loading service partners...</div>;
  }

  if (partners.length === 0) {
    return (
      <div className="text-gray-400 text-center py-4">
        No service partners found for this product.
      </div>
    );
  }

  return (
    <div className="space-y-3 mt-4">
      {partners.map(partner => (
        <div key={partner.id} className="border border-gray-700 rounded-md p-3">
          <div className="flex justify-between">
            <div>
              <div className="flex items-center space-x-2">
                <h4 className="font-bold">{partner.name}</h4>
                <button 
                  onClick={() => togglePartnerExpansion(partner.id)}
                  className="text-gray-400 hover:text-white"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={expandedPartnerId === partner.id ? "M5 15l7-7 7 7" : "M19 9l-7 7-7-7"} />
                  </svg>
                </button>
              </div>
              <p className="text-sm text-gray-400">Service: {partner.service}</p>
              <p className="text-sm text-gray-400">Location: {partner.location}</p>
              <p className="text-sm text-gray-400">
                Contact: {partner.email} | {partner.phone}
              </p>
              {partner.calendly_url && (
                <p className="text-sm text-blue-400 mt-1">
                  <a href={partner.calendly_url} target="_blank" rel="noopener noreferrer">
                    Calendly Booking Link
                  </a>
                </p>
              )}
              {partner.has_custom_slots && (
                <div className="mt-1">
                  <span className="text-sm text-green-400">Custom booking enabled</span>
                </div>
              )}
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => onEdit(partner)}
                className="text-blue-400 hover:text-blue-300"
                title="Edit partner"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
              </button>
              <button
                onClick={() => onDelete(partner.id)}
                className="text-red-400 hover:text-red-300"
                title="Delete partner"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </div>
          
          {expandedPartnerId === partner.id && (
            <div className="mt-3 pt-3 border-t border-gray-700">
              <div className="flex space-x-3">
                {partner.has_custom_slots && (
                  <button 
                    onClick={() => setShowTimeSlots(true)}
                    className={`px-3 py-1 rounded text-sm ${showTimeSlots ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
                  >
                    Manage Time Slots
                  </button>
                )}
              </div>
              
              {showTimeSlots && partner.has_custom_slots && (
                <div className="mt-3">
                  <TimeSlotManager 
                    partnerId={partner.id} 
                    partnerName={partner.name}
                    getAuthHeader={getAuthHeader}
                    onUpdate={() => fetchPartners()}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// Time Slot Manager Component
const TimeSlotManager = ({ partnerId, partnerName, getAuthHeader, onUpdate }) => {
  const [timeSlots, setTimeSlots] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [date, setDate] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [price, setPrice] = useState('');
  const [currency, setCurrency] = useState('USD');
  const [addingSlot, setAddingSlot] = useState(false);

  useEffect(() => {
    fetchTimeSlots();
  }, [partnerId]);

  const fetchTimeSlots = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API}/service-partners/${partnerId}/timeslots`, getAuthHeader());
      setTimeSlots(response.data);
    } catch (error) {
      console.error('Error fetching time slots:', error);
      toast.error('Failed to load time slots');
    } finally {
      setLoading(false);
    }
  };

  const handleAddTimeSlot = async (e) => {
    e.preventDefault();

    if (!date || !startTime || !endTime || !price) {
      toast.error('All fields are required');
      return;
    }

    // Validate price is a number
    const priceNumber = parseFloat(price);
    if (isNaN(priceNumber) || priceNumber <= 0) {
      toast.error('Price must be a positive number');
      return;
    }

    setAddingSlot(true);
    try {
      await axios.post(
        `${API}/service-partners/${partnerId}/timeslots`,
        {
          date,
          start_time: startTime,
          end_time: endTime,
          price: priceNumber,
          currency
        },
        getAuthHeader()
      );

      // Reset form
      setDate('');
      setStartTime('');
      setEndTime('');
      setPrice('');
      setShowAddForm(false);
      
      toast.success('Time slot added successfully');
      
      // Refresh time slots
      await fetchTimeSlots();
      
      // Notify parent component
      if (onUpdate) {
        onUpdate();
      }
    } catch (error) {
      console.error('Error adding time slot:', error);
      toast.error(error.response?.data?.detail || 'Failed to add time slot');
    } finally {
      setAddingSlot(false);
    }
  };

  const handleDeleteTimeSlot = async (slotId) => {
    if (!window.confirm('Are you sure you want to delete this time slot?')) {
      return;
    }

    try {
      await axios.delete(
        `${API}/service-partners/${partnerId}/timeslots/${slotId}`,
        getAuthHeader()
      );
      
      toast.success('Time slot deleted successfully');
      
      // Refresh time slots
      await fetchTimeSlots();
      
      // Notify parent component
      if (onUpdate) {
        onUpdate();
      }
    } catch (error) {
      console.error('Error deleting time slot:', error);
      toast.error('Failed to delete time slot');
    }
  };

  return (
    <div className="time-slot-manager">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium">Time Slots for {partnerName}</h3>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
        >
          {showAddForm ? 'Cancel' : 'Add Time Slot'}
        </button>
      </div>

      {showAddForm && (
        <div className="bg-gray-800 p-3 rounded mb-4">
          <form onSubmit={handleAddTimeSlot} className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-sm text-gray-300 mb-1">Date</label>
                <input
                  type="date"
                  value={date}
                  onChange={(e) => setDate(e.target.value)}
                  className="admin-input w-full"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">Start Time</label>
                <input
                  type="time"
                  value={startTime}
                  onChange={(e) => setStartTime(e.target.value)}
                  className="admin-input w-full"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">End Time</label>
                <input
                  type="time"
                  value={endTime}
                  onChange={(e) => setEndTime(e.target.value)}
                  className="admin-input w-full"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-1">Price</label>
                <div className="flex">
                  <select
                    value={currency}
                    onChange={(e) => setCurrency(e.target.value)}
                    className="admin-input rounded-r-none w-20"
                  >
                    <option value="USD">$</option>
                    <option value="EUR">€</option>
                    <option value="GBP">£</option>
                  </select>
                  <input
                    type="number"
                    min="0.01"
                    step="0.01"
                    value={price}
                    onChange={(e) => setPrice(e.target.value)}
                    placeholder="49.99"
                    className="admin-input rounded-l-none flex-1"
                    required
                  />
                </div>
              </div>
            </div>
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={addingSlot}
                className="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700 disabled:opacity-50"
              >
                {addingSlot ? 'Adding...' : 'Add Time Slot'}
              </button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div className="text-center py-4 text-gray-400">Loading time slots...</div>
      ) : timeSlots.length === 0 ? (
        <div className="text-center py-4 text-gray-400">No time slots available. Add one to get started.</div>
      ) : (
        <div className="space-y-2">
          <div className="grid grid-cols-5 gap-2 text-sm font-medium text-gray-400 pb-2 border-b border-gray-700">
            <div>Date</div>
            <div>Time</div>
            <div>Price</div>
            <div>Status</div>
            <div></div>
          </div>
          {timeSlots.map(slot => (
            <div key={slot.id} className="grid grid-cols-5 gap-2 text-sm py-2 border-b border-gray-800">
              <div>{new Date(slot.date).toLocaleDateString()}</div>
              <div>{slot.start_time} - {slot.end_time}</div>
              <div>{slot.currency === 'USD' ? '$' : slot.currency === 'EUR' ? '€' : '£'}{parseFloat(slot.price).toFixed(2)}</div>
              <div>
                {slot.available ? (
                  <span className="text-green-400">Available</span>
                ) : (
                  <span className="text-red-400">Booked</span>
                )}
              </div>
              <div className="text-right">
                {slot.available && (
                  <button
                    onClick={() => handleDeleteTimeSlot(slot.id)}
                    className="text-red-400 hover:text-red-300"
                    title="Delete time slot"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Service Partner Form Component
const ServicePartnerForm = ({ partner, productId, onSave, onCancel, getAuthHeader }) => {
  const [name, setName] = useState(partner ? partner.name : '');
  const [service, setService] = useState(partner ? partner.service : '');
  const [location, setLocation] = useState(partner ? partner.location : '');
  const [email, setEmail] = useState(partner ? partner.email : '');
  const [phone, setPhone] = useState(partner ? partner.phone : '');
  const [calendlyUrl, setCalendlyUrl] = useState(partner ? partner.calendly_url || '' : '');
  const [bookingType, setBookingType] = useState(partner ? (partner.calendly_url ? 'calendly' : (partner.has_custom_slots ? 'custom' : 'none')) : 'none');
  const [selectedProductId, setSelectedProductId] = useState(partner ? partner.product_id : productId || '');
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingProducts, setLoadingProducts] = useState(true);

  // Fetch available products
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await axios.get(`${API}/websites`, getAuthHeader());
        setProducts(response.data);
      } catch (error) {
        console.error('Error fetching products:', error);
        toast.error('Failed to load products');
      } finally {
        setLoadingProducts(false);
      }
    };

    fetchProducts();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!name || !service || !location || !email || !phone || !selectedProductId) {
      toast.error('All fields are required');
      return;
    }

    if (bookingType === 'calendly' && !calendlyUrl) {
      toast.error('Calendly URL is required when using Calendly for bookings');
      return;
    }

    setLoading(true);

    const partnerData = {
      name,
      service,
      location,
      email,
      phone,
      product_id: selectedProductId,
      has_custom_slots: bookingType === 'custom',
      calendly_url: bookingType === 'calendly' ? calendlyUrl : null
    };

    try {
      if (partner) {
        // Update existing partner
        await axios.put(
          `${API}/service-partners/${partner.id}`,
          partnerData,
          getAuthHeader()
        );
        toast.success('Service partner updated successfully');
      } else {
        // Create new partner
        await axios.post(
          `${API}/service-partners`,
          partnerData,
          getAuthHeader()
        );
        toast.success('Service partner added successfully');
      }
      onSave();
    } catch (error) {
      console.error('Error saving service partner:', error);
      toast.error(error.response?.data?.detail || 'Failed to save service partner');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="admin-input w-full"
          placeholder="Partner Name"
          required
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Service</label>
        <input
          type="text"
          value={service}
          onChange={(e) => setService(e.target.value)}
          className="admin-input w-full"
          placeholder="Repair, Installation, Support, etc."
          required
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Location</label>
        <input
          type="text"
          value={location}
          onChange={(e) => setLocation(e.target.value)}
          className="admin-input w-full"
          placeholder="City, State, Country"
          required
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="admin-input w-full"
          placeholder="contact@example.com"
          required
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Phone</label>
        <input
          type="text"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          className="admin-input w-full"
          placeholder="+1 (555) 123-4567"
          required
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Product</label>
        {loadingProducts ? (
          <div className="text-gray-400">Loading products...</div>
        ) : (
          <select
            value={selectedProductId}
            onChange={(e) => setSelectedProductId(e.target.value)}
            className="admin-input w-full"
            required
          >
            <option value="">Select a product</option>
            {products.map(product => (
              <option key={product.id} value={product.id}>
                {product.title}
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="space-y-3">
        <label className="block text-sm font-medium text-gray-300 mb-1">Booking Options</label>
        
        <div className="space-y-2">
          <div className="flex items-center">
            <input
              type="radio"
              id="booking-none"
              name="booking-type"
              value="none"
              checked={bookingType === 'none'}
              onChange={() => setBookingType('none')}
              className="h-4 w-4 text-blue-600 mr-2"
            />
            <label htmlFor="booking-none" className="text-gray-300">No online booking</label>
          </div>
          
          <div className="flex items-center">
            <input
              type="radio"
              id="booking-calendly"
              name="booking-type"
              value="calendly"
              checked={bookingType === 'calendly'}
              onChange={() => setBookingType('calendly')}
              className="h-4 w-4 text-blue-600 mr-2"
            />
            <label htmlFor="booking-calendly" className="text-gray-300">Use Calendly</label>
          </div>
          
          <div className="flex items-center">
            <input
              type="radio"
              id="booking-custom"
              name="booking-type"
              value="custom"
              checked={bookingType === 'custom'}
              onChange={() => setBookingType('custom')}
              className="h-4 w-4 text-blue-600 mr-2"
            />
            <label htmlFor="booking-custom" className="text-gray-300">Custom time slots with payment</label>
          </div>
        </div>
        
        {bookingType === 'calendly' && (
          <div className="mt-2">
            <input
              type="url"
              value={calendlyUrl}
              onChange={(e) => setCalendlyUrl(e.target.value)}
              className="admin-input w-full"
              placeholder="https://calendly.com/your-link"
              required={bookingType === 'calendly'}
            />
            <p className="text-xs text-gray-400 mt-1">
              Enter your full Calendly scheduling URL
            </p>
          </div>
        )}
        
        {bookingType === 'custom' && (
          <div className="mt-2 bg-gray-700 p-3 rounded">
            <p className="text-sm text-gray-300">
              You'll be able to add time slots after saving this service partner.
            </p>
          </div>
        )}
      </div>
      
      <div className="flex space-x-3">
        <button
          type="submit"
          disabled={loading}
          className="admin-button bg-blue-600 hover:bg-blue-700"
        >
          {loading ? 'Saving...' : (partner ? 'Update Partner' : 'Add Partner')}
        </button>
        
        <button
          type="button"
          onClick={onCancel}
          className="bg-gray-700 text-white px-4 py-2 rounded-md hover:bg-gray-600"
        >
          Cancel
        </button>
      </div>
    </form>
  );
};

// Service Partner Management Component
const ServicePartnerManager = () => {
  const [showForm, setShowForm] = useState(false);
  const [editingPartner, setEditingPartner] = useState(null);
  const [filterProductId, setFilterProductId] = useState('');
  const [products, setProducts] = useState([]);
  const [loadingProducts, setLoadingProducts] = useState(true);
  const { user } = useAuth();
  
  const getAuthHeader = () => ({
    headers: { Authorization: `Bearer ${user.token}` }
  });
  
  // Fetch available products
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await axios.get(`${API}/websites`, getAuthHeader());
        setProducts(response.data);
      } catch (error) {
        console.error('Error fetching products:', error);
        toast.error('Failed to load products');
      } finally {
        setLoadingProducts(false);
      }
    };

    fetchProducts();
  }, []);
  
  const handleAddPartner = () => {
    setEditingPartner(null);
    setShowForm(true);
  };
  
  const handleEditPartner = (partner) => {
    setEditingPartner(partner);
    setShowForm(true);
  };
  
  const handleDeletePartner = async (partnerId) => {
    if (window.confirm('Are you sure you want to delete this service partner?')) {
      try {
        await axios.delete(`${API}/service-partners/${partnerId}`, getAuthHeader());
        toast.success('Service partner deleted successfully');
        // Refresh the list
        setShowForm(false);
        setEditingPartner(null);
      } catch (error) {
        console.error('Error deleting service partner:', error);
        toast.error('Failed to delete service partner');
      }
    }
  };
  
  const handleSavePartner = () => {
    setShowForm(false);
    setEditingPartner(null);
  };
  
  return (
    <div className="admin-container mb-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold">Service Partners</h2>
        
        {!showForm && (
          <button
            onClick={handleAddPartner}
            className="admin-button bg-green-600 hover:bg-green-700"
          >
            Add Service Partner
          </button>
        )}
      </div>
      
      {showForm ? (
        <ServicePartnerForm
          partner={editingPartner}
          productId={filterProductId}
          onSave={handleSavePartner}
          onCancel={() => {
            setShowForm(false);
            setEditingPartner(null);
          }}
          getAuthHeader={getAuthHeader}
        />
      ) : (
        <>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Filter by Product
            </label>
            
            {loadingProducts ? (
              <div className="text-gray-400">Loading products...</div>
            ) : (
              <select
                value={filterProductId}
                onChange={(e) => setFilterProductId(e.target.value)}
                className="admin-input w-full"
              >
                <option value="">All Products</option>
                {products.map(product => (
                  <option key={product.id} value={product.id}>
                    {product.title}
                  </option>
                ))}
              </select>
            )}
          </div>
          
          <ServicePartnerList
            productId={filterProductId}
            onEdit={handleEditPartner}
            onDelete={handleDeletePartner}
            getAuthHeader={getAuthHeader}
          />
        </>
      )}
    </div>
  );
};

// Admin Dashboard - Website URL Management
const WebsiteManager = () => {
  const [websites, setWebsites] = useState([]);
  const [title, setTitle] = useState('');
  const [url, setUrl] = useState('');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState({});
  const [apiKey, setApiKey] = useState('');
  const [apiKeyStatus, setApiKeyStatus] = useState(false);
  const [checkingApiKey, setCheckingApiKey] = useState(true);
  const [activeTab, setActiveTab] = useState('info');  // 'info', 'pdfs'
  const [activeProductId, setActiveProductId] = useState(null);
  const [pendingPdfFiles, setPendingPdfFiles] = useState([]);
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  
  // Get auth header for API requests
  const getAuthHeader = () => ({
    headers: { Authorization: `Bearer ${user.token}` }
  });
  
  // Fetch websites on component mount
  useEffect(() => {
    fetchWebsites();
    checkApiKeyStatus();
  }, []);
  
  const fetchWebsites = async () => {
    try {
      const response = await axios.get(`${API}/websites`, getAuthHeader());
      setWebsites(response.data);
    } catch (error) {
      console.error('Error fetching websites:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error('Failed to load websites');
      }
    }
  };

  const checkApiKeyStatus = async () => {
    setCheckingApiKey(true);
    try {
      const response = await axios.get(`${API}/config/api-key/status`, getAuthHeader());
      setApiKeyStatus(response.data.has_api_key);
    } catch (error) {
      console.error('Error checking API key status:', error);
    } finally {
      setCheckingApiKey(false);
    }
  };
  
  const handleAddWebsite = async (e) => {
    e.preventDefault();
    
    if (!url.trim() || !title.trim()) {
      toast.error('URL and title are required');
      return;
    }
    
    setLoading(true);
    
    try {
      // First, create the website/product
      const response = await axios.post(`${API}/websites`, {
        url,
        title,
        description: description || undefined
      }, getAuthHeader());
      
      const newWebsiteId = response.data.id;
      
      // If there are PDFs to upload, process them
      if (pendingPdfFiles.length > 0) {
        toast.success('Product created successfully. Uploading PDFs...');
        
        // Upload each PDF file
        for (const file of pendingPdfFiles) {
          const formData = new FormData();
          formData.append('file', file);
          
          try {
            await axios.post(
              `${API}/websites/${newWebsiteId}/pdfs`,
              formData,
              {
                ...getAuthHeader(),
                headers: {
                  ...getAuthHeader().headers,
                  'Content-Type': 'multipart/form-data'
                }
              }
            );
          } catch (pdfError) {
            console.error(`Error uploading PDF ${file.name}:`, pdfError);
            toast.error(`Failed to upload PDF: ${file.name}`);
          }
        }
        
        toast.success(`Uploaded ${pendingPdfFiles.length} PDF${pendingPdfFiles.length !== 1 ? 's' : ''}`);
      } else {
        toast.success('Product added successfully');
      }
      
      // Reset form
      setUrl('');
      setTitle('');
      setDescription('');
      setPendingPdfFiles([]);
      
      // Refresh list
      await fetchWebsites();
      
    } catch (error) {
      console.error('Error adding website:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error(error.response?.data?.detail || 'Failed to add website');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const handleDeleteWebsite = async (id) => {
    if (!window.confirm('Are you sure you want to delete this website?')) {
      return;
    }
    
    try {
      await axios.delete(`${API}/websites/${id}`, getAuthHeader());
      await fetchWebsites();
      toast.success('Website deleted successfully');
    } catch (error) {
      console.error('Error deleting website:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error('Failed to delete website');
      }
    }
  };
  
  const handleRefreshWebsite = async (id) => {
    setRefreshing(prev => ({ ...prev, [id]: true }));
    
    try {
      await axios.post(`${API}/websites/${id}/refresh`, {}, getAuthHeader());
      await fetchWebsites();
      toast.success('Website content refreshed');
    } catch (error) {
      console.error('Error refreshing website:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error('Failed to refresh website content');
      }
    } finally {
      setRefreshing(prev => ({ ...prev, [id]: false }));
    }
  };
  
  const handleSetApiKey = async (e) => {
    e.preventDefault();
    
    if (!apiKey.trim()) {
      toast.error('API key is required');
      return;
    }
    
    try {
      await axios.post(`${API}/config/api-key`, {
        claude_api_key: apiKey
      }, getAuthHeader());
      
      setApiKey('');
      toast.success('API key updated successfully');
      checkApiKeyStatus();
    } catch (error) {
      console.error('Error setting API key:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error('Failed to update API key');
      }
    }
  };

  const handleRemoveApiKey = async () => {
    if (!window.confirm('Are you sure you want to remove the Claude API key? This will disable the chatbot functionality.')) {
      return;
    }
    
    try {
      await axios.delete(`${API}/config/api-key`, getAuthHeader());
      toast.success('API key removed successfully');
      checkApiKeyStatus();
    } catch (error) {
      console.error('Error removing API key:', error);
      if (error.response?.status === 401) {
        toast.error('Your session has expired. Please log in again.');
        logout();
        navigate('/login');
      } else {
        toast.error('Failed to remove API key');
      }
    }
  };
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleProductSelect = (id, tab = 'info') => {
    setActiveProductId(id);
    setActiveTab(tab);
  };

  const renderActiveProductContent = () => {
    if (!activeProductId) return null;
    
    const product = websites.find(w => w.id === activeProductId);
    if (!product) return null;
    
    return (
      <div className="bg-gray-800 rounded-lg p-4 mb-4">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-bold">{product.title}</h3>
          <button 
            onClick={() => setActiveProductId(null)}
            className="text-gray-400 hover:text-white"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="border-b border-gray-700 mb-4">
          <nav className="flex space-x-4">
            <button
              className={`py-2 px-3 ${activeTab === 'info' ? 'border-b-2 border-blue-500 text-white' : 'text-gray-400 hover:text-white'}`}
              onClick={() => setActiveTab('info')}
            >
              Information
            </button>
            <button
              className={`py-2 px-3 ${activeTab === 'pdfs' ? 'border-b-2 border-blue-500 text-white' : 'text-gray-400 hover:text-white'}`}
              onClick={() => setActiveTab('pdfs')}
            >
              PDF Documents
            </button>
          </nav>
        </div>
        
        {activeTab === 'info' && (
          <div>
            <div className="mb-4">
              <span className="text-gray-400">URL:</span> 
              <a href={product.url} target="_blank" rel="noreferrer" className="ml-2 text-blue-400 hover:underline">{product.url}</a>
            </div>
            
            {product.description && (
              <div className="mb-4">
                <span className="text-gray-400">Description:</span>
                <p className="mt-1 text-white">{product.description}</p>
              </div>
            )}
            
            <div className="flex space-x-3">
              <button
                onClick={() => handleRefreshWebsite(product.id)}
                disabled={refreshing[product.id]}
                className="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
              >
                {refreshing[product.id] ? 'Refreshing...' : 'Refresh Content'}
              </button>
              
              <button
                onClick={() => handleDeleteWebsite(product.id)}
                className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700"
              >
                Delete
              </button>
            </div>
          </div>
        )}
        
        {activeTab === 'pdfs' && (
          <div>
            <PDFUploader 
              productId={activeProductId} 
              getAuthHeader={getAuthHeader}
              onUploadComplete={() => fetchWebsites()}
            />
            
            <div className="mt-4">
              <PDFList 
                productId={activeProductId} 
                getAuthHeader={getAuthHeader}
                onRefresh={() => fetchWebsites()}
              />
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="container mx-auto p-4 max-w-4xl">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Admin Dashboard</h1>
        <button
          onClick={handleLogout}
          className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
        >
          Logout
        </button>
      </div>
      
      {/* Admin Navigation */}
      <div className="bg-gray-800 rounded-lg p-4 mb-6">
        <nav className="flex space-x-4">
          <div className="text-white px-3 py-2 rounded-md bg-gray-700">Products</div>
          <div className="text-white px-3 py-2 rounded-md hover:bg-gray-700" 
               onClick={() => navigate('/admin/service-partners')}>
            Service Partners
          </div>
        </nav>
      </div>
      
      {/* Active Product Detail View */}
      {renderActiveProductContent()}
      
      {/* API Key Configuration */}
      <div className="admin-container mb-6">
        <h2 className="text-xl font-bold mb-4">Claude API Configuration</h2>
        {checkingApiKey ? (
          <div className="text-gray-400 py-2">Checking API key status...</div>
        ) : (
          <>
            {apiKeyStatus ? (
              <div className="mb-4">
                <div className="flex items-center space-x-2 mb-3">
                  <div className="bg-green-500 h-3 w-3 rounded-full"></div>
                  <span className="text-green-400 font-medium">Claude API Key Connected</span>
                </div>
                <p className="text-gray-300 mb-4">
                  Your Claude API key is currently active. The chatbot is using this key to process queries.
                </p>
                <button
                  onClick={handleRemoveApiKey}
                  className="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-md"
                >
                  Remove API Key
                </button>
              </div>
            ) : (
              <form onSubmit={handleSetApiKey} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Claude API Key
                  </label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="Enter your Claude API key"
                    className="admin-input w-full"
                  />
                </div>
                <button
                  type="submit"
                  className="admin-button bg-purple-600 hover:bg-purple-700"
                >
                  Save API Key
                </button>
              </form>
            )}
          </>
        )}
      </div>

      {/* Stripe Configuration */}
      <div className="admin-container mb-6">
        <h2 className="text-xl font-bold mb-4">Stripe Payment Configuration</h2>
        <StripeConfigForm getAuthHeader={getAuthHeader} />
      </div>

      {/* Add Website Form */}
      <div className="admin-container mb-6">
        <h2 className="text-xl font-bold mb-4">Add Product</h2>
        <form onSubmit={handleAddWebsite} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Product Name or Website Title"
              className="admin-input w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              URL
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/product"
              className="admin-input w-full"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Description (Optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the product or website"
              className="admin-input w-full"
              rows="3"
            />
          </div>
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              PDF Documents (Optional)
            </label>
            <div className="p-3 border border-gray-700 rounded-md">
              <p className="text-sm text-gray-400 mb-2">
                Upload PDF documents for the chatbot to use when answering questions about this product.
              </p>
              <input
                type="file"
                accept=".pdf"
                multiple
                onChange={(e) => {
                  const files = Array.from(e.target.files).filter(
                    file => file.type === 'application/pdf'
                  );
                  setPendingPdfFiles(files);
                }}
                className="text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-gray-700 file:text-white hover:file:bg-gray-600"
              />
              
              {pendingPdfFiles.length > 0 && (
                <div className="mt-2 space-y-2">
                  <p className="text-sm font-medium text-gray-300">Selected PDF files:</p>
                  {pendingPdfFiles.map((file, index) => (
                    <div key={index} className="flex justify-between items-center bg-gray-700 rounded p-2">
                      <div className="flex items-center">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-red-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                        </svg>
                        <span className="text-sm truncate" title={file.name}>
                          {file.name} ({(file.size / 1024).toFixed(1)} KB)
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const newFiles = [...pendingPdfFiles];
                          newFiles.splice(index, 1);
                          setPendingPdfFiles(newFiles);
                        }}
                        className="text-red-400 hover:text-red-300 p-1"
                        title="Remove PDF"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="admin-button"
          >
            {loading ? 'Adding...' : 'Add Product'}
          </button>
        </form>
      </div>
      
      {/* Website List */}
      <div className="admin-container">
        <h2 className="text-xl font-bold mb-4">Managed Products</h2>
        
        {websites.length === 0 ? (
          <p className="text-gray-400">No products added yet.</p>
        ) : (
          <div className="space-y-4">
            {websites.map((site) => (
              <div key={site.id} className="border border-gray-700 rounded-md p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-bold text-white">{site.title}</h3>
                    <a 
                      href={site.url} 
                      target="_blank" 
                      rel="noreferrer"
                      className="text-blue-400 hover:underline text-sm"
                    >
                      {site.url}
                    </a>
                    {site.description && (
                      <p className="text-gray-400 mt-1">{site.description}</p>
                    )}
                    <p className="text-gray-500 text-xs mt-2">
                      Last scraped: {site.last_scraped ? new Date(site.last_scraped).toLocaleString() : 'Never'}
                    </p>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleRefreshWebsite(site.id)}
                      disabled={refreshing[site.id]}
                      className="text-green-400 hover:text-green-300 p-1"
                      title="Refresh content"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleDeleteWebsite(site.id)}
                      className="text-red-400 hover:text-red-300 p-1"
                      title="Delete website"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
                
                {/* Direct PDF Upload Section */}
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <h4 className="font-medium text-white mb-3">PDF Documents</h4>
                  
                  {/* PDF Upload Form */}
                  <div className="bg-gray-800 p-3 rounded-md mb-3">
                    <h5 className="text-sm font-medium text-blue-400 mb-2">Upload New PDF</h5>
                    <input
                      type="file"
                      accept=".pdf"
                      onChange={(e) => {
                        const file = e.target.files[0];
                        if (file && file.type === 'application/pdf') {
                          const formData = new FormData();
                          formData.append('file', file);
                          
                          toast.loading('Uploading PDF...');
                          axios.post(
                            `${API}/websites/${site.id}/pdfs`,
                            formData,
                            {
                              ...getAuthHeader(),
                              headers: {
                                ...getAuthHeader().headers,
                                'Content-Type': 'multipart/form-data'
                              }
                            }
                          ).then(() => {
                            toast.dismiss();
                            toast.success('PDF uploaded successfully');
                            fetchWebsites();
                            e.target.value = null; // Reset file input
                          }).catch(error => {
                            toast.dismiss();
                            toast.error('Failed to upload PDF');
                            console.error('Error uploading PDF:', error);
                          });
                        } else if (file) {
                          toast.error('Please select a valid PDF file');
                          e.target.value = null; // Reset file input
                        }
                      }}
                      className="text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-gray-700 file:text-white hover:file:bg-gray-600"
                    />
                  </div>
                  
                  {/* PDFs List */}
                  {site.pdfs && site.pdfs.length > 0 ? (
                    <div className="space-y-2">
                      {site.pdfs.map(pdf => (
                        <div key={pdf.id} className="flex justify-between items-center bg-gray-700 rounded p-2">
                          <div className="flex items-center">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-red-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                            </svg>
                            <span className="text-sm truncate" title={pdf.filename}>{pdf.filename}</span>
                          </div>
                          <button
                            onClick={() => {
                              if (window.confirm('Are you sure you want to delete this PDF?')) {
                                axios.delete(
                                  `${API}/websites/${site.id}/pdfs/${pdf.id}`,
                                  getAuthHeader()
                                ).then(() => {
                                  toast.success('PDF deleted successfully');
                                  fetchWebsites();
                                }).catch(error => {
                                  toast.error('Failed to delete PDF');
                                  console.error('Error deleting PDF:', error);
                                });
                              }
                            }}
                            className="text-red-400 hover:text-red-300 p-1"
                            title="Delete PDF"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-gray-400 text-sm">No PDFs uploaded yet</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// Navigation Component
const Navigation = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };
  
  return (
    <nav className="bg-black text-white p-4 border-b border-gray-800">
      <div className="container mx-auto flex justify-between items-center">
        <a href="/" className="text-xl font-bold">Ryan's Brain AI</a>
        <div className="space-x-4">
          <a href="/" className="hover:text-blue-300">Chat</a>
          {user ? (
            <>
              <a href="/admin" className="hover:text-blue-300">Admin</a>
              <button 
                onClick={handleLogout}
                className="hover:text-blue-300"
              >
                Logout
              </button>
            </>
          ) : (
            <a href="/login" className="hover:text-blue-300">Login</a>
          )}
        </div>
      </div>
    </nav>
  );
};

// Main App Component
function App() {
  return (
    <div className="App flex flex-col min-h-screen">
      <Toaster 
        position="top-right"
        toastOptions={{
          style: {
            background: '#333',
            color: '#fff',
          },
        }}
      />
      
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={
              <>
                <main className="flex-1 container mx-auto">
                  <Chat />
                </main>
              </>
            } />
            
            <Route path="/login" element={
              <>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <Login />
                </main>
              </>
            } />
            
            <Route path="/unauthorized" element={
              <>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <Unauthorized />
                </main>
              </>
            } />
            
            <Route path="/admin" element={
              <ProtectedRoute>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <WebsiteManager />
                </main>
              </ProtectedRoute>
            } />
            
            <Route path="/admin/service-partners" element={
              <ProtectedRoute>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <div className="container mx-auto p-4 max-w-4xl">
                    <div className="flex justify-between items-center mb-6">
                      <h1 className="text-2xl font-bold">Admin Dashboard</h1>
                      <a
                        href="/admin"
                        className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                      >
                        Back to Products
                      </a>
                    </div>
                    
                    {/* Admin Navigation */}
                    <div className="bg-gray-800 rounded-lg p-4 mb-6">
                      <nav className="flex space-x-4">
                        <div className="text-white px-3 py-2 rounded-md hover:bg-gray-700"
                             onClick={() => window.location.href = '/admin'}>
                          Products
                        </div>
                        <div className="text-white px-3 py-2 rounded-md bg-gray-700">
                          Service Partners
                        </div>
                      </nav>
                    </div>
                    
                    <ServicePartnerManager />
                  </div>
                </main>
              </ProtectedRoute>
            } />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </div>
  );
}

export default App;
