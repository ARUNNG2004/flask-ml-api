import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { Shield, Clock, MessageCircle } from 'lucide-react';
import { GlobalProvider } from './context/GlobalContext';
import StatusBadge from './components/StatusBadge';
import Scanner from './pages/Scanner';
import History from './pages/History';
import Chatbot from './pages/Chatbot';

function App() {
  return (
    <GlobalProvider>
      <Router>
        <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col font-sans selection:bg-indigo-500/30">
          {/* Header */}
          <header className="bg-gray-900 border-b border-gray-800 shadow-xl sticky top-0 z-50">
            <div className="max-w-7xl mx-auto px-4 lg:px-6 h-20 flex items-center justify-between">
              
              <div className="flex items-center space-x-3 cursor-pointer" onClick={() => window.location.href="/"}>
                <div className="bg-indigo-600/20 p-2 rounded-xl border border-indigo-500/30 shadow-inner">
                   <Shield className="w-7 h-7 text-indigo-400" />
                </div>
                <div>
                  <h1 className="text-xl lg:text-2xl font-black bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400 tracking-tight">
                    URLGuard
                  </h1>
                  <span className="hidden sm:block text-gray-500 text-xs font-bold tracking-widest uppercase mt-0.5">ML Threat Detector</span>
                </div>
              </div>
              
              <div className="flex items-center space-x-8">
                <nav className="hidden md:flex space-x-2">
                  <NavLink to="/scanner" className={({isActive}) => `px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide flex items-center space-x-2 transition-all ${isActive ? 'bg-gray-800 text-white shadow-inner border border-gray-700' : 'text-gray-400 hover:text-white hover:bg-gray-800/50'}`}>
                    <Shield className="w-4 h-4" /> <span>SCANNER</span>
                  </NavLink>
                  <NavLink to="/history" className={({isActive}) => `px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide flex items-center space-x-2 transition-all ${isActive ? 'bg-gray-800 text-white shadow-inner border border-gray-700' : 'text-gray-400 hover:text-white hover:bg-gray-800/50'}`}>
                    <Clock className="w-4 h-4" /> <span>HISTORY</span>
                  </NavLink>
                  <NavLink to="/chatbot" className={({isActive}) => `px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide flex items-center space-x-2 transition-all ${isActive ? 'bg-gray-800 text-white shadow-inner border border-gray-700' : 'text-gray-400 hover:text-white hover:bg-gray-800/50'}`}>
                    <MessageCircle className="w-4 h-4" /> <span>CHATBOT</span>
                  </NavLink>
                </nav>
                <div className="hidden lg:block h-8 w-px bg-gray-800"></div>
                <StatusBadge />
              </div>
            </div>
            
            {/* Mobile Nav */}
            <nav className="md:hidden flex bg-gray-950 border-t border-gray-800 p-2 gap-2">
              <NavLink to="/scanner" className={({isActive}) => `flex-1 py-3 rounded-lg text-center text-xs font-bold tracking-wider flex flex-col justify-center items-center space-y-1 transition-colors ${isActive ? 'bg-gray-800 text-white border border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}>
                <Shield className="w-5 h-5 mb-0.5" /> <span>SCANNER</span>
              </NavLink>
              <NavLink to="/history" className={({isActive}) => `flex-1 py-3 rounded-lg text-center text-xs font-bold tracking-wider flex flex-col justify-center items-center space-y-1 transition-colors ${isActive ? 'bg-gray-800 text-white border border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}>
                <Clock className="w-5 h-5 mb-0.5" /> <span>HISTORY</span>
              </NavLink>
              <NavLink to="/chatbot" className={({isActive}) => `flex-1 py-3 rounded-lg text-center text-xs font-bold tracking-wider flex flex-col justify-center items-center space-y-1 transition-colors ${isActive ? 'bg-gray-800 text-white border border-gray-700' : 'text-gray-500 hover:text-gray-300'}`}>
                <MessageCircle className="w-5 h-5 mb-0.5" /> <span>CHATBOT</span>
              </NavLink>
            </nav>
          </header>

          {/* Main Content */}
          <main className="flex-1 w-full max-w-7xl mx-auto p-4 md:p-8 shrink-0">
            <Routes>
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/history" element={<History />} />
              <Route path="/chatbot" element={<Chatbot />} />
              <Route path="*" element={<Navigate to="/scanner" replace />} />
            </Routes>
          </main>
        </div>
      </Router>
    </GlobalProvider>
  );
}

export default App;
