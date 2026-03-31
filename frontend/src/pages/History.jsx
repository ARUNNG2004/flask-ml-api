import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, Trash2, Search, RefreshCw, AlertTriangle, ShieldAlert, ChevronLeft, ChevronRight, Shield } from 'lucide-react';
import client from '../api/client';
import { useGlobal } from '../context/GlobalContext';

export default function History() {
  const navigate = useNavigate();
  const { historyRefreshTrigger } = useGlobal();
  
  const [loading, setLoading] = useState(true);
  const [records, setRecords] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage] = useState(20);
  const [filter, setFilter] = useState('all'); // all, safe, malicious
  const [search, setSearch] = useState('');
  
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [error, setError] = useState('');

  const fetchHistory = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await client.get(`/api/history?page=${page}&per_page=${perPage}&filter=${filter}`);
      setRecords(res.data.data.records || []);
      setTotal(res.data.data.total || 0);
    } catch (err) {
      setError('Failed to load history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, filter, historyRefreshTrigger]);

  // Auto-refresh via custom event from Scanner
  useEffect(() => {
    const handleScanSaved = () => {
      fetchHistory();
    };
    window.addEventListener('scan-saved', handleScanSaved);
    return () => window.removeEventListener('scan-saved', handleScanSaved);
  }, [page, filter]);

  const handleDelete = async (id) => {
    try {
      await client.delete(`/api/history/${id}`);
      fetchHistory();
    } catch (err) {
      alert('Failed to delete record: ' + err.message);
    }
  };

  const handleClearAll = async () => {
    try {
      await client.delete('/api/history');
      setShowClearConfirm(false);
      setPage(1);
      fetchHistory();
    } catch (err) {
      alert('Failed to clear history: ' + err.message);
    }
  };

  // Re-scan using sessionStorage
  const handleRescan = (url) => {
    sessionStorage.setItem('rescan_url', url);
    navigate('/scanner');
  };

  // Color based on NUMERIC risk_score, not string label
  const getScoreBadgeColor = (score) => {
    if (score <= 30) return 'bg-green-500/10 text-green-400 border-green-500/20';
    if (score <= 69) return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    return 'bg-red-500/10 text-red-400 border-red-500/20';
  };

  const getScoreLabel = (score) => {
    if (score <= 30) return 'Safe';
    if (score <= 69) return 'Suspicious';
    return 'Malicious';
  };

  const getPillColorByScore = (score) => {
    if (score == null) return 'bg-gray-800 text-gray-400 border-gray-700';
    if (score <= 30) return 'bg-green-900/30 text-green-400 border-green-800';
    if (score <= 69) return 'bg-orange-900/30 text-orange-400 border-orange-800';
    return 'bg-red-900/30 text-red-400 border-red-800';
  };

  const getLabelPillColor = (label) => {
    if (!label) return 'bg-gray-800 text-gray-400 border-gray-700';
    return label.toLowerCase() === 'malicious' 
      ? 'bg-red-900/30 text-red-400 border-red-800' 
      : 'bg-green-900/30 text-green-400 border-green-800';
  };

  // Client-side search filtering
  const filteredRecords = records.filter(r => 
    r.url && r.url.toLowerCase().includes(search.toLowerCase())
  );

  const totalPages = Math.ceil(total / perPage) || 1;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-2xl p-6 lg:p-8 animate-fade-in flex flex-col h-full min-h-[calc(100vh-120px)]">
      
      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight flex items-center">
            <Clock className="w-6 h-6 mr-3 text-indigo-400" />
            Scan History
          </h2>
          <p className="text-gray-400 text-sm mt-1">Review your previously analyzed URLs and their security verdicts.</p>
        </div>
        
        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
          {/* Filter Caps */}
          <div className="flex bg-gray-950 p-1 rounded-lg border border-gray-800">
            {['all', 'safe', 'malicious'].map(f => (
              <button
                key={f}
                onClick={() => { setFilter(f); setPage(1); }}
                className={`px-4 py-1.5 text-xs font-bold rounded-md capitalize transition-colors ${
                  filter === f ? 'bg-indigo-600 text-white shadow' : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          
          {/* Search Box */}
          <div className="relative flex-1 lg:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input 
              type="text" 
              placeholder="Filter by URL..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-sm text-gray-200 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          <button 
            onClick={() => setShowClearConfirm(true)}
            disabled={records.length === 0}
            className="flex items-center px-4 py-2 bg-red-900/20 text-red-500 hover:bg-red-900/40 hover:text-red-400 disabled:opacity-50 disabled:cursor-not-allowed text-xs font-bold border border-red-900/30 rounded-lg transition-colors"
          >
            <Trash2 className="w-4 h-4 mr-2" /> CLEAR ALL
          </button>
        </div>
      </div>

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 bg-black/80 flex justify-center items-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-sm w-full p-6 shadow-2xl">
            <div className="flex items-center mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 mr-3" />
              <h3 className="text-xl font-bold text-white">Clear History?</h3>
            </div>
            <p className="text-gray-400 mb-6">Are you sure you want to permanently delete all scan records? This action cannot be undone.</p>
            <div className="flex space-x-3 justify-end">
              <button onClick={() => setShowClearConfirm(false)} className="px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 font-medium">Cancel</button>
              <button onClick={handleClearAll} className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-bold shadow-lg">Yes, Delete All</button>
            </div>
          </div>
        </div>
      )}

      {/* Table Area */}
      <div className="flex-1 border border-gray-800 rounded-xl overflow-hidden bg-gray-950 flex flex-col">
        <div className="overflow-x-auto flex-1">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-gray-900/50 border-b border-gray-800 text-gray-400 tracking-wider text-xs uppercase">
                <th className="p-4 font-semibold w-40">Timestamp</th>
                <th className="p-4 font-semibold min-w-[200px]">URL Analyzed</th>
                <th className="p-4 font-semibold text-center">Score</th>
                <th className="p-4 font-semibold text-center">DT</th>
                <th className="p-4 font-semibold text-center">RF</th>
                <th className="p-4 font-semibold text-center">Ensemble</th>
                <th className="p-4 font-semibold text-center">Mode</th>
                <th className="p-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              
              {loading ? (
                // Skeletons
                Array(5).fill(0).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="p-4"><div className="h-4 bg-gray-800 rounded w-24"></div></td>
                    <td className="p-4"><div className="h-4 bg-gray-800 rounded w-full max-w-[300px]"></div></td>
                    <td className="p-4"><div className="h-6 bg-gray-800 rounded-full w-12 mx-auto"></div></td>
                    <td className="p-4"><div className="h-6 bg-gray-800 rounded-full w-16 mx-auto"></div></td>
                    <td className="p-4"><div className="h-6 bg-gray-800 rounded-full w-16 mx-auto"></div></td>
                    <td className="p-4"><div className="h-6 bg-gray-800 rounded-full w-16 mx-auto"></div></td>
                    <td className="p-4"><div className="h-4 bg-gray-800 rounded w-10 mx-auto"></div></td>
                    <td className="p-4 text-right"><div className="h-8 bg-gray-800 rounded w-20 ml-auto"></div></td>
                  </tr>
                ))
              ) : filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan="8" className="p-12 text-center text-gray-500">
                    <Shield className="w-12 h-12 mx-auto mb-4 opacity-30 saturate-0" />
                    {search ? 'No URLs match your search.' : 'No scans yet. Go to the Scanner tab to analyze your first URL.'}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-800/30 transition-colors group">
                    <td className="p-4 text-gray-400 tabular-nums text-xs">
                      {new Date(r.timestamp).toLocaleString(undefined, {
                        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                      })}
                    </td>
                    <td className="p-4">
                      <div className="text-gray-200 font-mono truncate max-w-[200px] sm:max-w-[300px] lg:max-w-[400px]" title={r.url}>
                        {r.url}
                      </div>
                    </td>
                    <td className="p-4 text-center">
                      <span className={`px-2.5 py-1 rounded inline-flex items-center justify-center font-black text-xs border ${getScoreBadgeColor(r.risk_score)}`}>
                        {r.risk_score}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      <span className={`px-2.5 py-0.5 rounded-sm border uppercase font-bold text-[10px] tracking-wider ${getLabelPillColor(r.dt_label)}`}>
                        {r.dt_label || 'N/A'}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      <span className={`px-2.5 py-0.5 rounded-sm border uppercase font-bold text-[10px] tracking-wider ${getLabelPillColor(r.rf_label)}`}>
                        {r.rf_label || 'N/A'}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      {/* Ensemble badge colored by numeric risk_score */}
                      <span className={`px-2.5 py-0.5 rounded border uppercase font-black text-xs tracking-wider shadow-sm ${getPillColorByScore(r.risk_score)}`}>
                        {getScoreLabel(r.risk_score)}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      <span className="text-xs text-gray-500 uppercase tracking-widest font-bold">{r.scan_mode}</span>
                    </td>
                    <td className="p-4 text-right">
                      <div className="flex items-center justify-end space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button 
                          onClick={() => handleRescan(r.url)}
                          className="p-1.5 bg-gray-800 text-gray-300 hover:text-white hover:bg-indigo-600 rounded transition-colors"
                          title="Re-scan"
                        >
                          <RefreshCw className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => handleDelete(r.id)}
                          className="p-1.5 bg-gray-800 text-gray-400 hover:text-red-400 hover:bg-red-900/30 rounded transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer — hide if total pages is 1 */}
        {totalPages > 1 && (
          <div className="border-t border-gray-800 p-4 bg-gray-900/50 flex items-center justify-between text-sm">
            <div className="text-gray-500">
              Showing <span className="font-medium text-gray-300">{Math.min((page - 1) * perPage + 1, total) || 0}</span> to <span className="font-medium text-gray-300">{Math.min(page * perPage, total)}</span> of <span className="font-medium text-gray-300">{total}</span>
            </div>
            <div className="flex space-x-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 border border-gray-700 rounded bg-gray-800 text-gray-300 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button 
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || total === 0}
                className="p-2 border border-gray-700 rounded bg-gray-800 text-gray-300 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
      
    </div>
  );
}
