import { useState, useEffect, useRef, createContext, useContext } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import { Toaster, toast } from 'react-hot-toast';
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
      localStorage.removeItem('token');
    } finally {
      setLoading(false);
    }
  };
  
  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/login`, { email, password });
      return { success: true, needsVerification: true };
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Login failed');
    }
  };
  
  const verify2FA = async (email, code) => {
    try {
      const response = await axios.post(`${API}/verify-2fa`, { email, code });
      const { access_token } = response.data;
      localStorage.setItem('token', access_token);
      await checkAuthStatus(access_token);
      return { success: true };
    } catch (error) {
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

// Chat Message Component
const ChatMessage = ({ message, isUser }) => {
  return (
    <div className={`my-2 ${isUser ? 'text-right' : 'text-left'}`}>
      <div
        className={`inline-block max-w-[80%] rounded-lg px-4 py-2 ${
          isUser
            ? 'bg-blue-600 text-white rounded-br-none'
            : 'bg-gray-200 text-gray-800 rounded-bl-none'
        }`}
      >
        {message}
      </div>
    </div>
  );
};

// Animated Chat Bubble for Assistant
const AnimatedChatBubble = ({ message }) => {
  return (
    <motion.div
      className="my-2 text-left"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3 }}
    >
      <motion.div
        className="inline-block max-w-[80%] rounded-lg px-4 py-2 bg-gray-200 text-gray-800 rounded-bl-none"
        initial={{ scale: 0.8 }}
        animate={{ 
          scale: [0.8, 1.05, 1],
          rotate: [-1, 1, -1, 1, 0]
        }}
        transition={{ 
          duration: 0.5,
          times: [0, 0.6, 1],
          ease: "easeInOut" 
        }}
      >
        <motion.span
          animate={{ opacity: [0, 1] }}
          transition={{ duration: 0.3 }}
        >
          {message}
        </motion.span>
      </motion.div>
    </motion.div>
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
      const result = await login(email, password);
      if (result.needsVerification) {
        setShowVerification(true);
        toast.success('Please check your email for a verification code');
      }
    } catch (error) {
      toast.error(error.message);
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
      const result = await verify2FA(email, code);
      if (result.success) {
        toast.success('Login successful');
        navigate('/admin');
      }
    } catch (error) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6 text-center">
        {showVerification ? 'Verify 2FA Code' : 'Admin Login'}
      </h2>
      
      {!showVerification ? (
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="admin@example.com"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="••••••••"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerify} className="space-y-4">
          <p className="text-gray-600 mb-4">
            A verification code has been sent to your email. Please enter it below.
          </p>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Verification Code
            </label>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="123456"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify Code'}
          </button>
          <button
            type="button"
            onClick={() => setShowVerification(false)}
            className="w-full bg-gray-200 text-gray-800 py-2 px-4 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500"
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
    <div className="max-w-lg mx-auto mt-20 p-6 bg-white rounded-lg shadow-lg text-center">
      <h2 className="text-2xl font-bold mb-4 text-red-600">Access Denied</h2>
      <p className="text-gray-700 mb-6">
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
  const chatContainerRef = useRef(null);
  
  // Scroll to bottom of chat when conversation updates
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [conversation]);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    
    if (!message.trim()) return;
    
    // Add user message to conversation
    setConversation(prev => [...prev, { content: message, role: 'user' }]);
    
    // Clear input field
    setMessage('');
    
    // Set loading state
    setLoading(true);
    
    try {
      const response = await axios.post(`${API}/chat`, {
        message: message,
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

  return (
    <div className="flex flex-col h-full bg-white shadow-md rounded-lg overflow-hidden">
      <div className="bg-blue-600 text-white p-4">
        <h2 className="text-xl font-bold">Product Assistant</h2>
        <p className="text-sm text-blue-100">Ask me anything about our products</p>
      </div>
      
      {/* Chat messages container */}
      <div 
        ref={chatContainerRef}
        className="flex-1 p-4 overflow-y-auto"
        style={{ maxHeight: 'calc(100vh - 240px)' }}
      >
        {conversation.length === 0 ? (
          <div className="text-center text-gray-500 my-8">
            <p>👋 Hi there! Ask me anything about our products.</p>
          </div>
        ) : (
          conversation.map((msg, index) => (
            msg.role === 'user' ? (
              <ChatMessage 
                key={index} 
                message={msg.content} 
                isUser={true} 
              />
            ) : (
              <AnimatedChatBubble
                key={index}
                message={msg.content}
              />
            )
          ))
        )}
        
        {/* Loading animation */}
        {loading && (
          <div className="my-2 text-left">
            <motion.div 
              className="inline-block bg-gray-200 text-gray-800 rounded-lg px-4 py-2 rounded-bl-none"
              animate={{
                scale: [1, 1.05, 1],
                rotate: [-1, 1, -1, 1, 0],
              }}
              transition={{
                duration: 1.5,
                repeat: Infinity,
                repeatType: "loop"
              }}
            >
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
            </motion.div>
          </div>
        )}
      </div>
      
      {/* Message input form */}
      <form onSubmit={handleSendMessage} className="p-4 border-t">
        <div className="flex space-x-2">
          <input
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Type your question here..."
            className="flex-1 border border-gray-300 rounded-full px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={loading}
          />
          <button
            type="submit"
            className="bg-blue-600 text-white rounded-full w-10 h-10 flex items-center justify-center hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            disabled={loading || !message.trim()}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
      </form>
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
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  
  // Get auth token for API requests
  const getAuthHeader = () => ({
    headers: { Authorization: `Bearer ${user.token}` }
  });
  
  // Fetch websites on component mount
  useEffect(() => {
    fetchWebsites();
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
  
  const handleAddWebsite = async (e) => {
    e.preventDefault();
    
    if (!url.trim() || !title.trim()) {
      toast.error('URL and title are required');
      return;
    }
    
    setLoading(true);
    
    try {
      await axios.post(`${API}/websites`, {
        url,
        title,
        description: description || undefined
      }, getAuthHeader());
      
      // Reset form
      setUrl('');
      setTitle('');
      setDescription('');
      
      // Refresh list
      await fetchWebsites();
      
      toast.success('Website added successfully');
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
  
  const handleLogout = () => {
    logout();
    navigate('/login');
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
      
      {/* API Key Configuration */}
      <div className="bg-white shadow-md rounded-lg p-6 mb-6">
        <h2 className="text-xl font-bold mb-4">Claude API Configuration</h2>
        <form onSubmit={handleSetApiKey} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Claude API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter your Claude API key"
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            className="bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500"
          >
            Save API Key
          </button>
        </form>
      </div>

      {/* Add Website Form */}
      <div className="bg-white shadow-md rounded-lg p-6 mb-6">
        <h2 className="text-xl font-bold mb-4">Add Website</h2>
        <form onSubmit={handleAddWebsite} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Product Name or Website Title"
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              URL
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/product"
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description (Optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the product or website"
              className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              rows="3"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {loading ? 'Adding...' : 'Add Website'}
          </button>
        </form>
      </div>
      
      {/* Website List */}
      <div className="bg-white shadow-md rounded-lg p-6">
        <h2 className="text-xl font-bold mb-4">Managed Websites</h2>
        
        {websites.length === 0 ? (
          <p className="text-gray-500">No websites added yet.</p>
        ) : (
          <div className="space-y-4">
            {websites.map((site) => (
              <div key={site.id} className="border rounded-md p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-bold">{site.title}</h3>
                    <a 
                      href={site.url} 
                      target="_blank" 
                      rel="noreferrer"
                      className="text-blue-600 hover:underline text-sm"
                    >
                      {site.url}
                    </a>
                    {site.description && (
                      <p className="text-gray-600 mt-1">{site.description}</p>
                    )}
                    <p className="text-gray-500 text-xs mt-2">
                      Last scraped: {site.last_scraped ? new Date(site.last_scraped).toLocaleString() : 'Never'}
                    </p>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleRefreshWebsite(site.id)}
                      disabled={refreshing[site.id]}
                      className="text-green-600 hover:text-green-800 p-1"
                      title="Refresh content"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleDeleteWebsite(site.id)}
                      className="text-red-600 hover:text-red-800 p-1"
                      title="Delete website"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
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
    <nav className="bg-gray-800 text-white p-4">
      <div className="container mx-auto flex justify-between items-center">
        <a href="/" className="text-xl font-bold">Product AI Chatbot</a>
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
    <div className="App flex flex-col min-h-screen bg-gray-100">
      <Toaster position="top-right" />
      
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={
              <>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <Chat />
                </main>
                <footer className="bg-gray-800 text-white p-4 text-center text-sm">
                  <p>© 2025 Product AI Chatbot. All rights reserved.</p>
                </footer>
              </>
            } />
            
            <Route path="/login" element={
              <>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <Login />
                </main>
                <footer className="bg-gray-800 text-white p-4 text-center text-sm">
                  <p>© 2025 Product AI Chatbot. All rights reserved.</p>
                </footer>
              </>
            } />
            
            <Route path="/unauthorized" element={
              <>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <Unauthorized />
                </main>
                <footer className="bg-gray-800 text-white p-4 text-center text-sm">
                  <p>© 2025 Product AI Chatbot. All rights reserved.</p>
                </footer>
              </>
            } />
            
            <Route path="/admin" element={
              <ProtectedRoute>
                <Navigation />
                <main className="flex-1 container mx-auto p-4">
                  <WebsiteManager />
                </main>
                <footer className="bg-gray-800 text-white p-4 text-center text-sm">
                  <p>© 2025 Product AI Chatbot. All rights reserved.</p>
                </footer>
              </ProtectedRoute>
            } />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </div>
  );
}

export default App;
