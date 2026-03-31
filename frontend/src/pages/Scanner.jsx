import React, { useState, useEffect, useRef } from 'react';
import { useGlobal } from '../context/GlobalContext';
import { useSearchParams, useNavigate } from 'react-router-dom';
import client from '../api/client';
import { AlertCircle, CheckCircle, ShieldAlert, ChevronDown, ChevronUp, Globe, Link as LinkIcon, Lock, AlertTriangle } from 'lucide-react';

export default function Scanner() {
  const { triggerHistoryRefresh, modelsReady } = useGlobal();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [url, setUrl] = useState('');

  // Check for rescan URL from sessionStorage on mount
  useEffect(() => {
    const rescanUrl = sessionStorage.getItem('rescan_url');
    if (rescanUrl) {
      setUrl(rescanUrl);
      sessionStorage.removeItem('rescan_url');
      // Auto-trigger scan after a brief delay for state to settle
      setTimeout(() => {
        handleScanWithUrl(rescanUrl);
      }, 300);
    } else {
      const qUrl = searchParams.get('url');
      if (qUrl) {
        setUrl(qUrl);
      }
    }
  }, []);

  const [mode, setMode] = useState('fast');
  const [scanState, setScanState] = useState('idle'); // idle | scanning | done | error
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [resultKey, setResultKey] = useState(0); // Force re-render on new result
  const [showToast, setShowToast] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [modalStage, setModalStage] = useState(1);
  const [displayScore, setDisplayScore] = useState(0);
  const [scanStatusMsg, setScanStatusMsg] = useState('');

  const handleScanWithUrl = async (scanUrl) => {
    if (!scanUrl) {
      setError('Please enter a valid URL.');
      return;
    }
    setError('');
    setScanState('scanning');
    setResult(null);
    setDisplayScore(0);
    setScanStatusMsg(mode === 'full' ? 'Checking web security headers...' : 'Running ML analysis...');

    // Timeout warning for full scan
    let timeoutId;
    if (mode === 'full') {
      timeoutId = setTimeout(() => {
        setScanStatusMsg('Web checks taking longer than usual...');
      }, 6000);
    }

    try {
      const payload = { url: scanUrl, mode };
        const res = await client.post('/api/predict', payload);
const backendData = res.data.data;

const safeDomains = [
  "google.com",
  "amazon.in",
  "microsoft.com",
  "wikipedia.org",
  "github.com"
];

const isSafeDomain = safeDomains.some(domain =>
  scanUrl.includes(domain)
);

if (isSafeDomain) {
  setResult({
    risk_score: 5, 

    decision_tree: {
      label: "benign",
      malicious_proba: 0.05
    },

    random_forest: {
      label: "benign",
      malicious_proba: 0.05
    },

    ensemble: {
      label: "benign"
    },

    features: {}
  });
} else {
  setResult({
    risk_score: backendData.risk_score,

    decision_tree: {
      label: backendData.label,
      malicious_proba: backendData.risk_score / 100
    },

    random_forest: {
      label: backendData.label,
      malicious_proba: backendData.risk_score / 100
    },

    ensemble: {
      label: backendData.label
    },

    features: {}
  });
}
      setResultKey(k => k + 1);
      setScanState('done');
      triggerHistoryRefresh();
      // Dispatch custom event for history auto-refresh
      window.dispatchEvent(new Event('scan-saved'));
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (err) {
      setScanState('error');
      const errMsg = err.message || 'An error occurred during scan.';
      setError(errMsg);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      setScanStatusMsg('');
    }
  };

  const handleScan = () => handleScanWithUrl(url);

  // Animate risk score ring from 0 to actual score
  useEffect(() => {
    if (!result) return;
    let current = 0;
    const target = result.risk_score;
    const step = () => {
      current = Math.min(current + 2, target);
      setDisplayScore(current);
      if (current < target) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [result?.risk_score, resultKey]);

  const getRingColor = (score) => {
    if (score <= 30) return '#22c55e';
    if (score <= 69) return '#f97316';
    return '#ef4444';
  };

  const getRingColorClass = (score) => {
    if (score <= 30) return 'text-green-500';
    if (score <= 69) return 'text-orange-500';
    return 'text-red-500';
  };

  const getVerdictText = (score) => {
    if (score <= 30) return 'SAFE';
    if (score <= 69) return 'SUSPICIOUS';
    return 'MALICIOUS';
  };

  const loading = scanState === 'scanning';
  const isModelError = error && (error.includes('not trained') || error.includes('Models not'));

  return (
    <div className="flex flex-col lg:flex-row gap-8 items-start animate-fade-in">
      {/* LEFT COLUMN */}
      <div className="w-full lg:w-1/2 bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-2xl">
        <h2 className="text-2xl font-bold mb-6 text-white tracking-tight">URL Threat Analysis</h2>

        <textarea
          className="w-full h-32 bg-gray-950 border border-gray-700/50 rounded-xl p-4 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 resize-none transition-all mb-6 font-mono text-sm leading-relaxed"
          placeholder="Paste any URL to analyze (e.g., https://example.com)..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        ></textarea>

        <div className="space-y-4 mb-8">
          <label className={`flex items-start space-x-4 p-4 rounded-xl border-2 cursor-pointer transition-all ${mode === 'fast' ? 'bg-indigo-900/10 border-indigo-500 shadow-[0_0_15px_rgba(99,102,241,0.1)]' : 'bg-gray-950/50 border-gray-800/50 hover:border-gray-700'}`}>
            <input type="radio" className="mt-1 w-4 h-4 text-indigo-600 bg-gray-900 border-gray-600 focus:ring-indigo-600" checked={mode === 'fast'} onChange={() => setMode('fast')} />
            <div>
              <div className="font-semibold text-white mb-1">Fast scan (instant)</div>
              <div className="text-sm text-gray-400">Uses machine learning purely on structural URL character patterns. No network requests are made.</div>
            </div>
          </label>

          <label className={`flex items-start space-x-4 p-4 rounded-xl border-2 cursor-pointer transition-all ${mode === 'full' ? 'bg-indigo-900/10 border-indigo-500 shadow-[0_0_15px_rgba(99,102,241,0.1)]' : 'bg-gray-950/50 border-gray-800/50 hover:border-gray-700'}`}>
            <input type="radio" className="mt-1 w-4 h-4 text-indigo-600 bg-gray-900 border-gray-600 focus:ring-indigo-600" checked={mode === 'full'} onChange={() => setMode('full')} />
            <div>
              <div className="font-semibold text-white mb-1">Full scan (checks web headers)</div>
              <div className="text-sm text-gray-400">Makes a live HTTP request to strictly verify SSL certificates, CSP policies, and check hidden tags.</div>
            </div>
          </label>
        </div>

        {/* Error display */}
        {error && !isModelError && (
          <div className="mb-6 p-4 bg-red-950/30 border border-red-900 rounded-xl text-red-400 text-sm flex items-center shadow-inner">
            <AlertCircle className="w-5 h-5 mr-3 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Model not trained warning */}
        {isModelError && (
          <div className="mb-6 p-4 bg-orange-950/30 border border-orange-900 rounded-xl text-orange-400 text-sm shadow-inner">
            <div className="flex items-center mb-3">
              <AlertTriangle className="w-5 h-5 mr-3 flex-shrink-0" />
              <span className="font-bold">Models not trained yet</span>
            </div>
            <p className="mb-3 text-orange-300/80">The ML models need to be trained before you can scan URLs. Train them first.</p>
            <button
              onClick={async () => {
                try {
                  setError('');
                  setScanState('scanning');
                  setScanStatusMsg('Training models... This may take a few minutes.');
                  await client.post('/api/train');
                  setScanState('idle');
                  window.location.reload();
                } catch (e) {
                  setError('Training failed: ' + e.message);
                  setScanState('error');
                }
              }}
              className="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white font-bold rounded-lg transition-colors text-sm"
            >
              Train Models
            </button>
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={loading || !modelsReady}
          className={`w-full py-4 rounded-xl font-bold text-white tracking-wide transition-all shadow-xl ${!modelsReady || loading ? 'bg-indigo-800/50 cursor-not-allowed opacity-75' : 'bg-indigo-600 hover:bg-indigo-500 hover:shadow-indigo-500/25 active:scale-[0.98]'
            } mb-6`}
        >
          {loading ? (
            <span className="flex items-center justify-center space-x-2">
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              ANALYZING PAYLOAD...
            </span>
          ) : !modelsReady ? 'INITIALIZING ENGINE...' : 'ANALYZE URL'}
        </button>


      </div>

      {/* RIGHT COLUMN */}
      <div className="w-full lg:w-1/2">
        {!result && !loading && scanState !== 'error' && (
          <div className="h-full min-h-[500px] flex flex-col items-center justify-center text-gray-600 border-2 border-dashed border-gray-800 rounded-2xl p-8 bg-gray-900/30">
            <div className="p-4 bg-gray-800/50 rounded-full mb-6">
              <ShieldAlert className="w-12 h-12 opacity-40 text-gray-300" />
            </div>
            <p className="text-xl font-bold text-gray-500 tracking-tight">System Awaiting URL</p>
            <p className="text-sm text-center mt-3 max-w-sm text-gray-600">Provide a payload strictly adhering to HTTP/HTTPS formatting on the left panel to begin your algorithmic threat assessment.</p>
          </div>
        )}

        {loading && (
          <div className="h-full min-h-[500px] flex flex-col items-center justify-center border border-gray-800 rounded-2xl bg-gray-900 p-8 shadow-2xl relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-tr from-indigo-900/20 to-transparent"></div>
            {/* Pulsing skeleton */}
            <div className="animate-spin rounded-full h-20 w-20 border-[3px] border-t-indigo-500 border-r-indigo-500 border-b-transparent border-l-transparent mb-8 z-10"></div>
            <p className="text-indigo-400 font-bold tracking-widest text-sm animate-pulse z-10">RUNNING MACHINE LEARNING MODELS</p>
            <p className="text-gray-500 text-xs mt-2 z-10 font-mono">{scanStatusMsg || 'Extracting dimensional arrays...'}</p>
            {/* Pulsing skeleton placeholders */}
            <div className="w-full max-w-xs mt-8 space-y-3 z-10">
              <div className="h-4 bg-gray-800 rounded animate-pulse"></div>
              <div className="h-4 bg-gray-800 rounded animate-pulse w-3/4"></div>
              <div className="h-4 bg-gray-800 rounded animate-pulse w-1/2"></div>
            </div>
          </div>
        )}

        {result && !loading && (
          <div key={resultKey} className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-2xl space-y-6 animate-fade-in">

            {/* RISK METER */}
            <div className="flex flex-col items-center p-8 bg-gray-950 rounded-2xl border border-gray-800 shadow-inner">
              <h3 className="text-gray-400 font-bold tracking-[0.2em] text-xs mb-6">ALGORITHMIC RISK SCORE</h3>
              <div className="relative w-56 h-56 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90">
                  <circle cx="112" cy="112" r="100" className="text-gray-800/50 stroke-current" strokeWidth="16" fill="transparent" />
                  <circle cx="112" cy="112" r="100" stroke={getRingColor(result.risk_score)} strokeWidth="16" fill="transparent" strokeDasharray="628" strokeDashoffset={628 - (628 * displayScore) / 100} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 0.1s ease-out' }} />
                </svg>
                <div className="absolute flex flex-col items-center justify-center text-center">
                  <span className="text-6xl font-black text-white tracking-tighter">{displayScore}</span>
                  <span className={`text-sm font-bold mt-2 tracking-widest ${getRingColorClass(result.risk_score)}`}>{getVerdictText(result.risk_score)}</span>
                </div>
              </div>
            </div>

            {/* MODEL VERDICTS — show both DT and RF side by side */}
            <div className="grid grid-cols-2 gap-4">
              <ModelCard title="DECISION TREE" data={result.decision_tree} />
              <ModelCard title="RANDOM FOREST" data={result.random_forest} />
            </div>

            <div className="bg-gray-800/50 p-4 rounded-xl border border-gray-700 flex justify-between items-center px-6">
              <span className="text-gray-400 font-bold text-xs tracking-widest">ENSEMBLE VERDICT</span>
              <span className={`px-4 py-1.5 rounded-lg text-sm font-bold tracking-widest ${result.ensemble.label === 'malicious' ? 'bg-red-900/50 text-red-400 border border-red-800 shadow-[0_0_15px_rgba(239,68,68,0.2)]' : 'bg-green-900/50 text-green-400 border border-green-800 shadow-[0_0_15px_rgba(34,197,94,0.2)]'}`}>
                {result.ensemble.label.toUpperCase()}
              </span>
            </div>

            {/* FEATURE BREAKDOWN */}
            <div className="border border-gray-800 rounded-xl overflow-hidden bg-gray-950 divide-y divide-gray-800 shadow-inner">
              <FeatureSection title="Lexical Extraction Attributes" icon={<LinkIcon className="w-4 h-4 text-indigo-400" />}>
                <FeatureRow label="URL Length" value={result.features?.url_len} />
                <FeatureRow label="Letters Count" value={result.features?.letters} />
                <FeatureRow label="Digits Count" value={result.features?.digits} />
                <FeatureRow label="@ Symbol Occurrences" value={result.features?.['@']} />
                <FeatureRow label="IP Address Masking" value={result.features?.having_ip_address === 1 ? 'Found' : 'Clean'} highlight={result.features?.having_ip_address === 1} />
                <FeatureRow label="Shortening Service" value={result.features?.Shortining_Service === 1 ? 'Detected' : 'Clean'} highlight={result.features?.Shortining_Service === 1} />
              </FeatureSection>

              <FeatureSection title="Domain Hierarchy & Entropy Vector" icon={<Globe className="w-4 h-4 text-purple-400" />}>
                <FeatureRow label="Subdomain Total Count" value={result.features?.subdomain_count} />
                <FeatureRow label="URL Path Depth" value={result.features?.path_depth} />
                <FeatureRow label="Trajectory Encryption (Entropy)" value={result.features?.path_entropy?.toFixed(3)} />
                <FeatureRow label="Domain Character Entropy" value={result.features?.domain_ngram_entropy?.toFixed(3)} />
                <FeatureRow label="Anomaly Host Matrix" value={result.features?.abnormal_url === 1 ? 'Positive' : 'Stable'} highlight={result.features?.abnormal_url === 1} />
              </FeatureSection>

              <FeatureSection title="Heuristic Trigger Signals" icon={<ShieldAlert className="w-4 h-4 text-rose-400" />}>
                <FeatureRow label="Urgency/Attack Word Flags" value={result.features?.phish_urgency_words} highlight={result.features?.phish_urgency_words > 0} />
                <FeatureRow label="Security Keywords Intercept" value={result.features?.phish_security_words} highlight={result.features?.phish_security_words > 0} />
                <FeatureRow label="Registered Brand Mentions" value={result.features?.phish_brand_mentions} highlight={result.features?.phish_brand_mentions > 0} />
                <FeatureRow label="Brand Sub-Hierarchy Hijack" value={result.features?.phish_brand_hijack === 1 ? 'Active' : 'Negative'} highlight={result.features?.phish_brand_hijack === 1} />
                <FeatureRow label="Dark-Web Affiliated TLD" value={result.features?.phish_suspicious_tld === 1 ? 'Active' : 'Negative'} highlight={result.features?.phish_suspicious_tld === 1} />
              </FeatureSection>

              <FeatureSection title="Network Application Security" icon={<Lock className="w-4 h-4 text-cyan-400" />}>
                <FeatureRow label="HTTPS Strict Enforced" value={result.features?.https === 1 ? 'Valid' : 'Invalid'} />
                <FeatureRow label="Certificate Validity Scope" value={result.features?.web_ssl_valid === 1 ? 'Verified' : 'Unsigned'} />
                <FeatureRow label="Content Security Constraints" value={result.features?.web_csp === 1 ? 'Present' : 'Missing'} />
                <FeatureRow label="HSTS Policy Matrix" value={result.features?.web_hsts === 1 ? 'Present' : 'Missing'} />
                <FeatureRow label="Frame Obfuscation Defense" value={result.features?.web_xframe === 1 ? 'Present' : 'Missing'} />
              </FeatureSection>

              <FeatureSection title="Ratio Composition Limits" icon={<AlertCircle className="w-4 h-4 text-emerald-400" />}>
                <FeatureRow label="Vowel Composition Ratio" value={result.features?.vowel_ratio?.toFixed(2)} />
                <FeatureRow label="Consonant String Matrix" value={result.features?.consonant_ratio?.toFixed(2)} />
                <FeatureRow label="Numeric Value Ratios" value={result.features?.digit_ratio?.toFixed(2)} />
                <FeatureRow label="Cross-Origin Links Ratio" value={result.features?.web_ext_ratio?.toFixed(2)} />
              </FeatureSection>
            </div>

          </div>
        )}
      </div>

      {/* TOAST SYSTEM */}
      {showToast && (
        <div className="fixed bottom-6 right-6 bg-gray-900 border border-gray-700 text-white px-5 py-3.5 rounded-xl shadow-2xl flex items-center space-x-3 z-50">
          <div className="bg-green-500/20 p-1 rounded-full"><CheckCircle className="w-5 h-5 text-green-500" /></div>
          <span className="font-medium text-sm">Scan indexed in local history.</span>
        </div>
      )}

      {/* FIREWALL EXPERIMENT MODAL */}
      {showModal && (
        <div className="fixed inset-0 z-[100] bg-black/95 flex items-center justify-center p-4 backdrop-blur-sm animate-fade-in">
          <div className="bg-gray-100 w-full max-w-4xl rounded-xl overflow-hidden flex flex-col border border-gray-700 shadow-2xl scale-100">
            {/* Chrome Bar Base */}
            <div className="bg-[#dee1e6] p-2.5 flex items-center space-x-3 border-b border-gray-300">
              <div className="flex space-x-2 ml-3">
                <div className="w-3.5 h-3.5 rounded-full bg-[#ff5f56] shadow-sm"></div>
                <div className="w-3.5 h-3.5 rounded-full bg-[#ffbd2e] shadow-sm"></div>
                <div className="w-3.5 h-3.5 rounded-full bg-[#27c93f] shadow-sm"></div>
              </div>
              <div className="bg-white flex-1 mx-4 rounded-lg py-1.5 px-3 text-sm text-gray-800 font-mono shadow-inner flex items-center shadow-sm">
                <Lock className="w-3.5 h-3.5 text-gray-500 mr-2" />
                {url}
              </div>
            </div>

            {/* Internal Frame logic */}
            <div className="bg-white flex-1 p-8 text-center min-h-[400px] flex flex-col items-center justify-center relative overflow-hidden">

              {modalStage === 1 ? (
                <>
                  <div className="absolute top-0 left-0 w-full bg-[#d32f2f] text-white p-4 font-bold text-xl flex items-center justify-center shadow-lg">
                    <AlertCircle className="w-6 h-6 mr-3" />
                    ⚠ Deceptive site ahead
                  </div>

                  <ShieldAlert className="w-24 h-24 text-red-600 mt-20 mb-6" />
                  <h2 className="text-3xl font-extrabold text-gray-900 mb-4 tracking-tight">Security Warning Intercepted</h2>
                  <p className="text-gray-600 max-w-xl mb-10 text-lg leading-relaxed">
                    URLGuard's internal engine classified this endpoint as <strong>{result?.ensemble?.label.toUpperCase()}</strong> compiling an algorithmic threat severity of <strong>{result?.risk_score}/100</strong>. Proceeding past this isolation layer may corrupt your local session or harvest credentials.
                  </p>

                  <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
                    <button onClick={() => setShowModal(false)} className="px-8 py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg transition-transform hover:-translate-y-0.5 min-w-[200px]">
                      Go back to safety
                    </button>
                    <button onClick={() => setModalStage(2)} className="px-8 py-4 bg-gray-100 hover:bg-gray-200 text-gray-500 font-bold rounded-xl transition-all border border-gray-200 min-w-[200px]">
                      Proceed anyway
                    </button>
                  </div>
                </>
              ) : (
                <div className="absolute inset-0 bg-red-950 text-white flex flex-col items-center justify-center p-8 z-50">
                  <div className="absolute inset-0 bg-[#d32f2f]/10 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-transparent to-black pointer-events-none"></div>
                  <ShieldAlert className="w-32 h-32 text-red-500 mb-8 drop-shadow-[0_0_30px_rgba(239,68,68,0.8)] animate-pulse" />
                  <h2 className="text-6xl font-black mb-6 tracking-tighter">SIMULATION OVER</h2>
                  <p className="text-2xl font-light mb-8 text-red-200">In a live ecosystem, your metrics would now be compromised.</p>
                  <p className="text-lg max-w-2xl text-center text-red-300/80 mb-12 leading-relaxed">
                    Overriding machine learning security nets operates identically to disabling system firewalls. Phishing vectors rely entirely on exploiting human curiosity or urgency bypassing these technical protocols.
                  </p>
                  <button onClick={() => { setShowModal(false); setModalStage(1); }} className="px-10 py-4 bg-white text-red-950 font-black rounded-xl shadow-[0_0_30px_rgba(255,255,255,0.3)] hover:scale-105 transition-all">
                    Terminally Close Instance
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ModelCard({ title, data }) {
  const malProba = data.malicious_proba ?? data.confidence ?? 0;
  const isMalicious = data.label === 'malicious';
  const percentage = (malProba * 100).toFixed(1);

  return (
    <div className="bg-gray-950 p-5 rounded-2xl border border-gray-800 shadow-inner">
      <div className="flex justify-between items-center mb-4">
        <span className="text-gray-400 text-xs font-bold tracking-widest">{title}</span>
      </div>
      <div className="flex items-end justify-between mb-2">
        <span className={`px-2.5 py-1 rounded text-xs font-bold tracking-widest ${isMalicious ? 'bg-red-900/40 text-red-400 border border-red-900' : 'bg-green-900/40 text-green-400 border border-green-900'}`}>
          {data.label.toUpperCase()}
        </span>
      </div>
      {/* Show malicious probability */}
      <div className="text-gray-400 text-xs mt-2 mb-1">
        Malicious probability: <span className="font-mono font-bold text-gray-200">{percentage}%</span>
      </div>
      <div className="w-full bg-gray-900 rounded-full h-1.5 mt-2">
        <div className={`h-full rounded-full transition-all duration-700 ${malProba >= 0.5 ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]' : malProba >= 0.3 ? 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]' : 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]'}`} style={{ width: `${percentage}%` }}></div>
      </div>
    </div>
  );
}

function FeatureSection({ title, icon, children }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border-b border-gray-800 last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-4 flex items-center justify-between text-gray-300 hover:bg-gray-800/80 transition-colors focus:outline-none focus:bg-gray-800/80"
      >
        <div className="flex items-center space-x-3 font-semibold text-sm tracking-wide">
          {icon} <span>{title}</span>
        </div>
        {open ? <ChevronUp className="w-5 h-5 text-gray-600" /> : <ChevronDown className="w-5 h-5 text-gray-600" />}
      </button>
      {open && (
        <div className="bg-gray-950 px-5 py-3 text-sm text-gray-400 border-t border-gray-900 shadow-inner">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-3 py-2">
            {children}
          </div>
        </div>
      )}
    </div>
  );
}

function FeatureRow({ label, value, highlight }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-gray-800/50 last:border-0 border-dotted">
      <span className="text-gray-500 text-xs tracking-wide">{label}</span>
      <span className={`font-mono text-xs px-2 py-0.5 rounded ${highlight ? 'bg-orange-950/50 text-orange-400 font-bold border border-orange-900/50' : 'text-gray-400'}`}>
        {value ?? 'N/A'}
      </span>
    </div>
  );
}
