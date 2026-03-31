import React, { useState, useEffect, useRef } from 'react';
import { Send, Trash2, Shield, User } from 'lucide-react';
import client from '../api/client';
import TypingIndicator from '../components/TypingIndicator';

export default function Chatbot() {
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const bottomRef = useRef(null);

  // Initial Welcome
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([
        {
          id: Date.now(),
          role: 'bot',
          text: "Hello! I'm your cybersecurity awareness assistant. I can help you understand phishing attacks, URL safety, and online security best practices. What would you like to know?",
          suggestions: ["What is phishing?", "How to spot a phishing URL?", "Give me safety tips", "How does this scanner work?"],
          timestamp: new Date().toISOString()
        }
      ]);
    }
  }, [messages.length]);

  // Auto-scroll to bottom after each new message or typing state change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const sendMessage = async (text) => {
    if (!text.trim()) return;

    // Add user message
    const userMsg = {
      id: Date.now(),
      role: 'user',
      text: text,
      suggestions: [],
      timestamp: new Date().toISOString()
    };
    
    setMessages(prev => [...prev, userMsg]);
    setInputValue('');
    setIsTyping(true);

    try {
      const res = await client.post('/api/chat', { message: text });
      const data = res.data.data;
      
      // Handle both nested and flat response formats
      let botResponseText = '';
      let botSuggestions = [];

      if (data.response && typeof data.response === 'object') {
        // Nested: data.response.response
        botResponseText = data.response.response || "I couldn't process that.";
        botSuggestions = data.response.suggestions || [];
      } else if (typeof data.response === 'string') {
        // Flat: data.response is the text
        botResponseText = data.response;
        botSuggestions = data.suggestions || [];
      } else {
        botResponseText = "I couldn't process that request.";
        botSuggestions = [];
      }

      // Typing indicator disappears AFTER bot response arrives
      setIsTyping(false);
      
      // Add bot message
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        role: 'bot',
        text: botResponseText,
        suggestions: botSuggestions,
        timestamp: new Date().toISOString()
      }]);
    } catch (e) {
      setIsTyping(false);
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        role: 'bot',
        text: "Sorry, I couldn't connect to the server.",
        suggestions: ["Try again"],
        timestamp: new Date().toISOString()
      }]);
    }
  };

  // Suggestion chips must trigger actual API call
  const handleSuggestion = (text) => {
    sendMessage(text);
  };

  const clearChat = () => {
    setMessages([
      {
        id: Date.now(),
        role: 'bot',
        text: "Conversation cleared. How can I help you regarding cybersecurity today?",
        suggestions: ["What is phishing?", "How to spot a phishing URL?", "Give me safety tips"],
        timestamp: new Date().toISOString()
      }
    ]);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-120px)] lg:h-[calc(100vh-140px)] bg-gray-950 border border-gray-800 rounded-2xl shadow-2xl overflow-hidden animate-fade-in relative z-0">
      
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex justify-between items-center shrink-0">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-500/20 rounded-lg">
            <Shield className="w-6 h-6 text-indigo-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">Security Assistant</h2>
            <div className="flex items-center space-x-2 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-green-500"></span>
              <span className="text-xs text-gray-400 font-medium">Online</span>
            </div>
          </div>
        </div>
        
        <button 
          onClick={clearChat}
          className="p-2 bg-gray-800 hover:bg-red-900/30 text-gray-400 hover:text-red-400 rounded-lg transition-colors group flex items-center"
          title="Clear Conversation"
        >
          <Trash2 className="w-5 h-5" />
        </button>
      </div>

      {/* Message List */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
        {messages.map((msg, idx) => (
          <div key={msg.id || idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            
            {msg.role === 'bot' && (
              <div className="w-8 h-8 rounded-full bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center mr-3 shrink-0 mt-1 shadow-inner">
                <Shield className="w-4 h-4 text-indigo-400" />
              </div>
            )}
            
            <div className={`max-w-[85%] lg:max-w-[70%] flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
              <div 
                className={`py-3 px-4 shadow-md ${
                  msg.role === 'user' 
                    ? 'bg-indigo-600 text-white rounded-2xl rounded-tr-sm' 
                    : 'bg-gray-800 border border-gray-700 text-gray-200 rounded-2xl rounded-tl-sm'
                }`}
              >
                {/* Text rendered paragraph-by-paragraph */}
                <div className="leading-relaxed text-[15px]">
                  {msg.text.split('\n').map((paragraph, i) => (
                    <React.Fragment key={i}>
                      {paragraph}
                      {i !== msg.text.split('\n').length - 1 && <br />}
                    </React.Fragment>
                  ))}
                </div>
              </div>
              
              <span className="text-[10px] text-gray-500 mt-1.5 font-medium px-1">
                {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>

              {/* Suggestion Chips — CLICKABLE and trigger API call */}
              {msg.suggestions && msg.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-3 pl-1">
                  {msg.suggestions.map((suggestion, sIdx) => (
                    <button
                      key={sIdx}
                      onClick={() => handleSuggestion(suggestion)}
                      disabled={isTyping}
                      className="px-3 py-1.5 bg-gray-900 border border-gray-700 hover:border-indigo-500 hover:text-indigo-300 text-gray-300 text-xs rounded-full transition-all shadow-sm active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {msg.role === 'user' && (
              <div className="w-8 h-8 rounded-full bg-gray-700/50 border border-gray-600 flex items-center justify-center ml-3 shrink-0 mt-1 shadow-inner">
                <User className="w-4 h-4 text-gray-400" />
              </div>
            )}
            
          </div>
        ))}

        {isTyping && (
          <div className="flex justify-start">
            <div className="w-8 h-8 rounded-full bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center mr-3 shrink-0 mt-1 shadow-inner">
              <Shield className="w-4 h-4 text-indigo-400" />
            </div>
            <TypingIndicator />
          </div>
        )}

        {/* Auto-scroll anchor */}
        <div ref={bottomRef} className="h-4" />
      </div>

      {/* Input Area */}
      <div className="bg-gray-900 border-t border-gray-800 p-4 shrink-0">
        <form 
          onSubmit={(e) => { e.preventDefault(); sendMessage(inputValue); }} 
          className="flex items-center gap-3 w-full bg-gray-950 p-2 rounded-xl border border-gray-700 focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500/50 transition-all shadow-inner"
        >
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            disabled={isTyping}
            placeholder={isTyping ? "Bot is typing..." : "Type your security question here..."}
            className="flex-1 bg-transparent border-none text-gray-100 placeholder-gray-500 px-3 focus:outline-none focus:ring-0 disabled:opacity-50 text-[15px]"
          />
          <button
            type="submit"
            disabled={!inputValue.trim() || isTyping}
            className="p-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            title="Send Message"
          >
            <Send className="w-5 h-5 -ml-0.5" />
          </button>
        </form>
      </div>

    </div>
  );
}
