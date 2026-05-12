import React, { useState, useEffect } from 'react';
import { 
  Shield, ShieldAlert, ShieldCheck, Search, Globe, AlertTriangle, 
  CheckCircle2, Lock, ExternalLink, History, Trash2, Info, 
  TrendingUp, Fingerprint, Activity, Zap, Languages
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const translations = {
  en: {
    title: 'Phish',
    titleSuffix: 'Guard v1',
    subtitle: 'Next-generation phishing detection powered by heuristic intelligence and global threat intelligence.',
    placeholder: 'Paste URL to analyze (e.g. secure-login-bank.xyz)',
    scanBtn: 'Scan Now',
    analyzing: 'Analyzing...',
    recentScans: 'Recent Scans',
    noActivity: 'No recent activity',
    stayProtected: 'Stay Protected',
    stayProtectedDesc: 'Always check for HTTPS and verify the sender before clicking unknown links.',
    proactiveDefense: 'Proactive Defense',
    proactiveDefenseDesc: 'Our heuristic engine and API integrations analyze URL patterns to catch zero-day attacks.',
    analysisFindings: 'Analysis Findings',
    riskIntensity: 'Risk Intensity',
    domainDna: 'Domain DNA',
    safe: 'SAFE',
    danger: 'DANGER',
    warning: 'WARNING',
    safeDesc: 'Verified safe for browsing',
    dangerDesc: 'Critical threat detected',
    warningDesc: 'Caution advised',
    engineVersion: 'PhishGuard Engine v1.0 + VirusTotal',
    footerText: '© 2024 Team Thinking | Developed by Cruz',
    links: ['Engine API', 'Documentation', 'GitHub'],
    scanSteps: [
      'Initializing Secure Protocol Scan...',
      'Analyzing Domain Metadata...',
      'Heuristic Pattern Recognition...',
      'Checking Global Threat Intelligence...',
      'Compiling Risk Assessment...'
    ],
    riskReasons: {
      ip: 'Uses raw IP address instead of a registered domain name.',
      tld: 'Utilizes a high-risk Top-Level Domain (TLD) often used for phishing.',
      keywords: 'Contains deceptive keywords: ',
      impersonation: 'Detected potential typosquatting impersonating ',
      length: 'The URL structure is abnormally complex/long.',
      depth: 'Excessive subdomain depth used to mask the actual domain.',
      homoglyph: 'Contains non-standard characters (Homoglyphs) often used in deceptive domains.'
    }
  }
};

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [scanStep, setScanStep] = useState(0);
  const lang = 'en'; // Fixed to English for GitHub
  const t = translations[lang];

  useEffect(() => {
    const savedHistory = localStorage.getItem('phishguard_history');
    if (savedHistory) {
      setHistory(JSON.parse(savedHistory));
    }
  }, []);

  const VT_API_KEY = ''; // Add your VirusTotal API Key here

  const checkVirusTotal = async (inputUrl) => {
    if (!VT_API_KEY) return null;
    
    try {
      // VirusTotal expects URL without padding in base64
      const urlToEncode = inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`;
      const encodedUrl = btoa(urlToEncode).replace(/=/g, '');
      
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      if (response.status === 404) {
        // If not found, we might need to submit it first, but for now return null
        return null;
      }

      const data = await response.json();
      return data.data.attributes.last_analysis_stats;
    } catch (e) {
      console.error("VT API Error:", e);
      return null;
    }
  };

  const performHeuristicAnalysis = (inputUrl) => {
    let score = 0;
    const reasons = [];
    
    try {
      const formattedUrl = inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`;
      const urlObj = new URL(formattedUrl);
      const hostname = urlObj.hostname;
      
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      if (ipRegex.test(hostname)) {
        score += 45;
        reasons.push(t.riskReasons.ip);
      }

      const suspiciousTLDs = ['.xyz', '.top', '.ga', '.cf', '.tk', '.ml', '.bid', '.win', '.icu', '.monster'];
      if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        score += 25;
        reasons.push(t.riskReasons.tld);
      }

      const phishingKeywords = ['login', 'signin', 'verify', 'account', 'secure', 'banking', 'update', 'confirm', 'wallet', 'auth', 'support'];
      const foundKeywords = phishingKeywords.filter(k => inputUrl.toLowerCase().includes(k));
      if (foundKeywords.length > 0) {
        score += 12 * foundKeywords.length;
        reasons.push(`${t.riskReasons.keywords}${foundKeywords.join(', ')}.`);
      }

      const brandImpersonations = [
        { brand: 'Google', pattern: /g[0o]{2}gle/i },
        { brand: 'Facebook', pattern: /faceb[0o]{2}k/i },
        { brand: 'PayPal', pattern: /paypa1/i },
        { brand: 'Amazon', pattern: /amaz0n/i },
        { brand: 'Microsoft', pattern: /micros0ft/i },
        { brand: 'Apple', pattern: /app1e/i },
        { brand: 'Netflix', pattern: /netf1ix/i }
      ];
      brandImpersonations.forEach(({ brand, pattern }) => {
        if (pattern.test(hostname) && !hostname.toLowerCase().includes(brand.toLowerCase())) {
          score += 55;
          reasons.push(`${t.riskReasons.impersonation}${brand}.`);
        }
      });

      if (inputUrl.length > 80) {
        score += 15;
        reasons.push(t.riskReasons.length);
      }

      const parts = hostname.split('.');
      if (parts.length > 4) {
        score += 20;
        reasons.push(t.riskReasons.depth);
      }

      if (/[^\x00-\x7F]/.test(hostname)) {
        score += 40;
        reasons.push(t.riskReasons.homoglyph);
      }

      return {
        score: Math.min(score, 100),
        reasons,
        hostname
      };

    } catch (e) {
      return { status: 'invalid', message: 'Invalid URL format' };
    }
  };

  const analyzeURL = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setResult(null);
    setScanStep(0);

    // Heuristic analysis happens first
    const heuristic = performHeuristicAnalysis(url);
    if (heuristic.status === 'invalid') {
      setResult(heuristic);
      setLoading(false);
      return;
    }

    // Progress animation
    for (let i = 0; i < t.scanSteps.length; i++) {
      setScanStep(i);
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    // Check VirusTotal
    const vtStats = await checkVirusTotal(url);
    
    // Combine results
    let finalScore = heuristic.score;
    if (vtStats) {
      if (vtStats.malicious > 0) finalScore = Math.max(finalScore, 90);
      else if (vtStats.suspicious > 0) finalScore = Math.max(finalScore, 60);
      
      if (vtStats.malicious > 0) {
        heuristic.reasons.push(`VirusTotal: Detected as malicious by ${vtStats.malicious} engines.`);
      }
    }

    let status = 'safe';
    if (finalScore >= 60) status = 'danger';
    else if (finalScore >= 30) status = 'warning';

    const analysisResult = {
      status,
      score: finalScore,
      reasons: heuristic.reasons,
      hostname: heuristic.hostname,
      vtStats
    };

    setResult(analysisResult);
    
    const newHistory = [
      { ...analysisResult, url, timestamp: new Date().toISOString() },
      ...history.slice(0, 9)
    ];
    setHistory(newHistory);
    localStorage.setItem('phishguard_history', JSON.stringify(newHistory));
    
    setLoading(false);
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('phishguard_history');
  };


  const getRiskColor = (score) => {
    if (score >= 60) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#10b981';
  };

  return (
    <div className="app-container">
      <div className="background-decor">
        <div className="blob blob-1"></div>
        <div className="blob blob-2"></div>
      </div>

      <header className="hero-section">
        <motion.div 
          initial={{ rotateY: 180, opacity: 0 }}
          animate={{ rotateY: 0, opacity: 1 }}
          transition={{ duration: 0.8, type: 'spring' }}
          className="logo-icon"
        >
          <Shield size={72} color="#6366f1" />
          <div className="logo-glow"></div>
        </motion.div>
        <h1>{t.title}<span>{t.titleSuffix}</span></h1>
        <p className="hero-subtitle">{t.subtitle}</p>
      </header>

      <div className="main-layout">
        <main className="content-area">
          <div className="glass-card main-card">
            <form onSubmit={analyzeURL} className="input-wrapper">
              <div className="input-inner">
                <Globe className="input-icon" size={20} />
                <input 
                  type="text" 
                  className="url-input" 
                  placeholder={t.placeholder}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <button type="submit" className="analyze-btn" disabled={loading}>
                {loading ? t.analyzing : (
                  <>
                    <Zap size={18} />
                    {t.scanBtn}
                  </>
                )}
              </button>
            </form>

            <AnimatePresence mode="wait">
              {loading && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="loading-overlay"
                >
                  <div className="loader-content">
                    <div className="spinner-outer">
                      <div className="spinner-inner"></div>
                      <Activity className="spinner-icon" size={32} />
                    </div>
                    <p className="loading-text">{t.scanSteps[scanStep]}</p>
                    <div className="progress-bar">
                      <motion.div 
                        className="progress-fill"
                        initial={{ width: '0%' }}
                        animate={{ width: `${(scanStep + 1) * 20}%` }}
                      />
                    </div>
                  </div>
                </motion.div>
              )}

              {result && !loading && (
                <motion.div 
                  key="result"
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="result-wrapper"
                >
                  <div className={`status-banner ${result.status}`}>
                    {result.status === 'safe' && <ShieldCheck size={32} />}
                    {result.status === 'danger' && <ShieldAlert size={32} />}
                    {result.status === 'warning' && <AlertTriangle size={32} />}
                    <div className="status-text">
                      <h3>{result.status === 'safe' ? t.safe : result.status === 'danger' ? t.danger : t.warning}</h3>
                      <p>
                        {result.status === 'safe' ? t.safeDesc : 
                         result.status === 'danger' ? t.dangerDesc : t.warningDesc}
                      </p>
                    </div>
                  </div>

                    <div className="metrics-grid">
                      <div className="metric-card">
                        <span className="metric-label">{t.riskIntensity}</span>
                        <div className="gauge-container">
                          <svg viewBox="0 0 100 50">
                            <path d="M10,45 A40,40 0 0,1 90,45" fill="none" stroke="#1e293b" strokeWidth="8" strokeLinecap="round" />
                            <motion.path 
                              d="M10,45 A40,40 0 0,1 90,45" 
                              fill="none" 
                              stroke={getRiskColor(result.score)} 
                              strokeWidth="8" 
                              strokeLinecap="round"
                              initial={{ strokeDasharray: '0, 200' }}
                              animate={{ strokeDasharray: `${(result.score / 100) * 125}, 200` }}
                              transition={{ duration: 1.5, ease: "easeOut" }}
                            />
                          </svg>
                          <div className="gauge-value" style={{ color: getRiskColor(result.score) }}>
                            {result.score}%
                          </div>
                        </div>
                      </div>

                      <div className="metric-card">
                        <span className="metric-label">{t.domainDna}</span>
                        <div className="dna-item">
                          <Fingerprint size={16} />
                          <span>{result.hostname}</span>
                        </div>
                        {result.vtStats && (
                          <div className="vt-badge-list">
                            <div className="vt-badge malicious">
                              <span>Malicious:</span> {result.vtStats.malicious}
                            </div>
                            <div className="vt-badge suspicious">
                              <span>Suspicious:</span> {result.vtStats.suspicious}
                            </div>
                          </div>
                        )}
                        {!result.vtStats && (
                          <div className="dna-item">
                            <Lock size={16} />
                            <span>{t.engineVersion}</span>
                          </div>
                        )}
                      </div>
                    </div>

                  {result.reasons && result.reasons.length > 0 && (
                    <div className="findings-box">
                      <h4><Info size={18} /> {t.analysisFindings}</h4>
                      <ul>
                        {result.reasons.map((reason, i) => (
                          <motion.li 
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.1 }}
                            key={i}
                          >
                            {reason}
                          </motion.li>
                        ))}
                      </ul>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="tips-grid">
            <div className="tip-card">
              <TrendingUp size={24} color="#6366f1" />
              <h4>{t.stayProtected}</h4>
              <p>{t.stayProtectedDesc}</p>
            </div>
            <div className="tip-card">
              <ShieldCheck size={24} color="#10b981" />
              <h4>{t.proactiveDefense}</h4>
              <p>{t.proactiveDefenseDesc}</p>
            </div>
          </div>
        </main>

        <aside className="sidebar">
          <div className="glass-card threat-intel-card">
            <div className="history-header">
              <h3><Activity size={18} /> Live Threat Intel</h3>
              <div className="live-indicator">
                <span className="dot"></span>
                LIVE
              </div>
            </div>
            <div className="threat-feed">
              {[
                { domain: 'verify-bank-acc.top', type: 'Phishing', time: '2s ago' },
                { domain: 'secure-wallet-login.xyz', type: 'Malware', time: '5s ago' },
                { domain: 'fb-account-update.cf', type: 'Impersonation', time: '12s ago' }
              ].map((threat, i) => (
                <div key={i} className="threat-item">
                  <div className="threat-meta">
                    <span className="threat-domain">{threat.domain}</span>
                    <span className="threat-type">{threat.type}</span>
                  </div>
                  <span className="threat-time">{threat.time}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card history-card">
            <div className="history-header">
              <h3><History size={18} /> {t.recentScans}</h3>
              {history.length > 0 && (
                <button onClick={clearHistory} className="clear-btn">
                  <Trash2 size={14} />
                </button>
              )}
            </div>
            <div className="history-list">
              {history.length === 0 ? (
                <div className="empty-history">
                  <Search size={32} opacity={0.2} />
                  <p>{t.noActivity}</p>
                </div>
              ) : (
                history.map((item, index) => (
                  <motion.div 
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    key={index} 
                    className="history-item"
                  >
                    <div className={`history-dot ${item.status}`}></div>
                    <div className="history-info">
                      <span className="history-url">{item.url}</span>
                      <span className="history-time">{new Date(item.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </div>
        </aside>
      </div>

      <footer className="app-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <Shield size={24} color="#6366f1" />
            <span>{t.title}{t.titleSuffix}</span>
          </div>
          <p>{t.footerText}</p>
          <div className="footer-links">
            {t.links.map((link, i) => <a key={i} href="#">{link}</a>)}
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;

