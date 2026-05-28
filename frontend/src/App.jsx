import React, { useState } from 'react'
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Loader2, 
  ChevronDown, 
  ChevronUp, 
  BookOpen, 
  Download, 
  ExternalLink, 
  Code, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  GraduationCap, 
  Info, 
  Copy, 
  Check,
  RefreshCw,
  HelpCircle,
  FileJson,
  FileText
} from 'lucide-react'

// Common sample domains for testing
const SUGGESTED_DOMAINS = [
  { name: 'Google (Secure)', url: 'google.com' },
  { name: 'GitHub (Highly Secure)', url: 'github.com' },
  { name: 'HTTPBin (Simple)', url: 'httpbin.org' },
  { name: 'HTTP Example', url: 'http://example.com' }
]

function App() {
  const [urlInput, setUrlInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const [expandedHeaders, setExpandedHeaders] = useState({})
  const [copiedHeader, setCopiedHeader] = useState(null)

  // Toggle header card expansion
  const toggleHeader = (headerName) => {
    setExpandedHeaders(prev => ({
      ...prev,
      [headerName]: !prev[headerName]
    }))
  }

  // Pre-fill input and run scan
  const handleSuggestClick = (url) => {
    setUrlInput(url)
    analyzeUrl(url)
  }

  // Add https:// if missing during submission
  const validateAndNormalizeUrl = (url) => {
    let target = url.trim()
    if (!target) return ''
    if (!/^https?:\/\//i.test(target)) {
      target = 'https://' + target
    }
    return target
  }

  const handleUrlInputChange = (e) => {
    setUrlInput(e.target.value)
  }

  const analyzeUrl = async (urlToScan) => {
    const targetUrl = urlToScan || urlInput
    if (!targetUrl.trim()) {
      setError('Please enter a valid URL or domain.')
      return
    }

    setLoading(true)
    setError('')
    setReport(null)

    const normalized = validateAndNormalizeUrl(targetUrl)

    try {
      const response = await fetch(`http://127.0.0.1:8000/analyze?url=${encodeURIComponent(normalized)}`)
      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.detail || 'An error occurred during header analysis.')
      }

      setReport(data)
      // Auto-expand all failing or warning headers to help student read them
      const initialExpanded = {}
      Object.keys(data.results).forEach(key => {
        if (data.results[key].status !== 'good') {
          initialExpanded[key] = true
        }
      })
      setExpandedHeaders(initialExpanded)
    } catch (err) {
      console.error(err)
      setError(err.message || 'Failed to connect to the backend server. Make sure the backend is running on http://127.0.0.1:8000')
    } finally {
      setLoading(false)
    }
  }

  const handleFormSubmit = (e) => {
    e.preventDefault()
    analyzeUrl()
  }

  // Copy recommendation to clipboard helper
  const copyToClipboard = (text, headerName) => {
    navigator.clipboard.writeText(text)
    setCopiedHeader(headerName)
    setTimeout(() => setCopiedHeader(null), 2000)
  }

  // Download JSON Report
  const downloadReport = () => {
    if (!report) return
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute("href", dataStr)
    const fileName = `security_headers_report_${report.scan_details.target_url.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`
    downloadAnchor.setAttribute("download", fileName)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  // Color mappings for UI elements based on status
  const getStatusColor = (status) => {
    switch (status) {
      case 'good':
        return 'text-emerald-400 bg-emerald-950/50 border-emerald-500/30'
      case 'warning':
        return 'text-amber-400 bg-amber-950/50 border-amber-500/30'
      case 'danger':
      default:
        return 'text-rose-400 bg-rose-950/50 border-rose-500/30'
    }
  }

  const getStatusBadge = (status) => {
    switch (status) {
      case 'good':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 size={12} /> Good
          </span>
        )
      case 'warning':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle size={12} /> Weak / Warning
          </span>
        )
      case 'danger':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle size={12} /> Missing / Critical
          </span>
        )
    }
  }

  const getGradeColor = (grade) => {
    switch (grade) {
      case 'A': return 'text-emerald-400 border-emerald-500'
      case 'B': return 'text-teal-400 border-teal-500'
      case 'C': return 'text-amber-400 border-amber-500'
      case 'D': return 'text-orange-400 border-orange-500'
      default: return 'text-rose-400 border-rose-500'
    }
  }

  const getGradeDescription = (grade) => {
    switch (grade) {
      case 'A': return 'Excellent Web Architecture Security!'
      case 'B': return 'Good security configuration with minor recommendations.'
      case 'C': return 'Fair security posture. Key headers are missing.'
      case 'D': return 'Weak web architecture. Vulnerable to common client-side exploits.'
      default: return 'Critical vulnerabilities detected! Highly susceptible to OWASP top attacks.'
    }
  }

  // Get aggregated recommendations for a quick panel
  const getAggregatedRecommendations = () => {
    if (!report) return []
    return Object.entries(report.results)
      .filter(([_, details]) => details.status !== 'good')
      .map(([name, details]) => ({
        name,
        status: details.status,
        recommendation: details.recommendation
      }))
  }

  const aggregatedRecs = getAggregatedRecommendations()

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 pb-20 selection:bg-indigo-500 selection:text-white gradient-bg">
      {/* Decorative top bar for SY0-701 educational focus */}
      <div className="bg-indigo-600 text-white py-1.5 px-4 text-center text-xs font-semibold tracking-wider uppercase flex items-center justify-center gap-2">
        <GraduationCap size={16} />
        CompTIA Security+ SY0-701 Educational Exam Reference Implementation
      </div>

      <header className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 pb-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 rounded-xl border border-indigo-500/20 text-indigo-400">
              <Shield size={32} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
                Security Header Analyzer
              </h1>
              <p className="text-xs sm:text-sm text-slate-400">
                Analyze HTTP headers, assess secure web architecture configurations, and study SY0-701 exam concepts.
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <span className="text-xs bg-slate-800 text-indigo-400 px-3 py-1 rounded-md border border-slate-700 font-mono">
              v1.0.0 (Vite + FastAPI)
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        
        {/* Search Bar / Input Panel */}
        <section className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl p-6 mb-8 shadow-xl">
          <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
            <Search size={18} className="text-indigo-400" />
            Scan Website Configuration
          </h2>
          <form onSubmit={handleFormSubmit} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-grow">
              <input
                type="text"
                value={urlInput}
                onChange={handleUrlInputChange}
                placeholder="Enter URL or Domain (e.g. github.com)"
                className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-xl py-3 pl-4 pr-12 text-slate-100 placeholder-slate-500 outline-none transition-all font-mono text-sm"
                disabled={loading}
              />
              {!urlInput.startsWith('http://') && !urlInput.startsWith('https://') && urlInput.trim() !== '' && (
                <span className="absolute right-3 top-3.5 text-[10px] text-indigo-400/70 font-semibold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                  Adds https://
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={loading}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-xl transition-all duration-150 flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/15"
            >
              {loading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <RefreshCw size={18} />
                  Analyze
                </>
              )}
            </button>
          </form>

          {/* Suggested quick links */}
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">Suggested test targets:</span>
            {SUGGESTED_DOMAINS.map((domain, index) => (
              <button
                key={index}
                type="button"
                onClick={() => handleSuggestClick(domain.url)}
                className="text-xs text-slate-400 bg-slate-950 border border-slate-800 hover:border-slate-700 hover:text-slate-200 px-2.5 py-1 rounded-lg transition-all"
              >
                {domain.name}
              </button>
            ))}
          </div>
        </section>

        {/* Error Callout */}
        {error && (
          <div className="bg-rose-950/30 border border-rose-500/30 text-rose-300 rounded-xl p-4 mb-8 flex gap-3 items-start animate-fadeIn">
            <ShieldAlert size={20} className="text-rose-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="font-bold text-rose-200">Scan Execution Failed</h3>
              <p className="text-sm mt-1">{error}</p>
              <div className="mt-3 text-xs text-rose-400/80">
                Tip: Verify the domain exists, responds to HTTP requests, and that the FastAPI backend runs on <code>localhost:8000</code>.
              </div>
            </div>
          </div>
        )}

        {/* Main Dashboard Display (After Scan) */}
        {report && (
          <div className="space-y-8 animate-fadeIn">
            
            {/* Summary Panel */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Score Circular Progress bar */}
              <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col items-center justify-center text-center">
                <h3 className="text-sm font-semibold text-slate-400 tracking-wider uppercase mb-4">
                  Overall Security Posture
                </h3>
                
                <div className="relative w-40 h-40 flex items-center justify-center">
                  {/* SVG Circle Progress */}
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className="stroke-slate-800 fill-none"
                      strokeWidth="8"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className={`fill-none stroke-current transition-all-500`}
                      style={{
                        strokeDasharray: 2 * Math.PI * 40,
                        strokeDashoffset: 2 * Math.PI * 40 * (1 - report.score / 100)
                      }}
                      strokeWidth="8"
                      strokeDasharray="251.2"
                      strokeLinecap="round"
                    />
                  </svg>
                  
                  {/* Center Score */}
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-5xl font-black ${getGradeColor(report.grade)}`}>
                      {report.grade}
                    </span>
                    <span className="text-sm text-slate-400 font-semibold mt-1">
                      {report.score} / 100
                    </span>
                  </div>
                </div>

                <div className="mt-4">
                  <p className="text-sm font-bold text-slate-200">
                    {getGradeDescription(report.grade)}
                  </p>
                </div>
              </div>

              {/* Scan Info details */}
              <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-400 tracking-wider uppercase mb-4">
                    Target details
                  </h3>
                  
                  <div className="space-y-3 font-mono text-xs sm:text-sm">
                    <div className="flex justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-slate-400">Target Host:</span>
                      <span className="text-white font-medium truncate max-w-[200px]" title={report.scan_details.target_url}>
                        {report.scan_details.target_url}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-slate-400">Final Landing:</span>
                      <a 
                        href={report.scan_details.final_url} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="text-indigo-400 font-medium truncate max-w-[200px] flex items-center gap-1 hover:underline"
                        title={report.scan_details.final_url}
                      >
                        {report.scan_details.final_url.replace(/^https?:\/\//i, '')}
                        <ExternalLink size={12} className="inline shrink-0" />
                      </a>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-slate-400">Status Response:</span>
                      <span className="text-emerald-400 font-medium">
                        {report.scan_details.status_code} OK
                      </span>
                    </div>
                    <div className="flex justify-between pb-2">
                      <span className="text-slate-400">Server Info:</span>
                      <span className="text-amber-400 font-medium truncate max-w-[150px]">
                        {report.scan_details.server}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-2 mt-6">
                  <button
                    onClick={downloadReport}
                    className="flex-grow bg-slate-850 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-200 font-semibold py-2.5 px-4 rounded-xl text-xs flex items-center justify-center gap-2 transition-all"
                  >
                    <Download size={14} /> Export JSON Report
                  </button>
                </div>
              </div>

              {/* Quick Recommendations summary */}
              <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-400 tracking-wider uppercase mb-3">
                    Action Plan Summary
                  </h3>
                  
                  {aggregatedRecs.length === 0 ? (
                    <div className="text-emerald-400 text-sm font-semibold flex items-center gap-2 mt-4">
                      <ShieldCheck size={18} />
                      Zero action required! All headers pass security validation.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {aggregatedRecs.map((rec, index) => (
                        <div key={index} className="flex gap-2 text-xs">
                          {rec.status === 'danger' ? (
                            <XCircle size={14} className="text-rose-500 shrink-0 mt-0.5" />
                          ) : (
                            <AlertTriangle size={14} className="text-amber-500 shrink-0 mt-0.5" />
                          )}
                          <div className="text-slate-300">
                            <span className="font-semibold text-slate-100">{rec.name}</span>: missing or needs tuning.
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="text-[11px] text-slate-500 border-t border-slate-800/80 pt-3 mt-4">
                  Showing {aggregatedRecs.length} issues to resolve for secure-by-default architecture alignment.
                </div>
              </div>

            </section>

            {/* Detailed Headers Analysis */}
            <section>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Code size={20} className="text-indigo-400" />
                  Individual Header Inspection
                </h3>
                <span className="text-xs text-slate-400">
                  Click on any header card to view learning objectives and recommendations.
                </span>
              </div>

              {/* Grid of Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(report.results).map(([headerName, details]) => {
                  const isExpanded = !!expandedHeaders[headerName]
                  const statusStyles = getStatusColor(details.status)

                  return (
                    <div 
                      key={headerName}
                      className={`bg-slate-900/40 border rounded-2xl overflow-hidden transition-all duration-200 ${
                        isExpanded ? 'ring-1 ring-indigo-500/30' : 'hover:border-slate-700'
                      } border-slate-800`}
                    >
                      {/* Card Header Header */}
                      <button
                        onClick={() => toggleHeader(headerName)}
                        className="w-full text-left p-5 flex items-center justify-between gap-4"
                      >
                        <div className="space-y-1 truncate">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-slate-100 font-mono text-sm sm:text-base tracking-tight">
                              {headerName}
                            </span>
                            {getStatusBadge(details.status)}
                          </div>
                          
                          <div className="text-xs text-slate-400 truncate max-w-md font-mono mt-1">
                            {details.value ? (
                              <span className="text-indigo-300">{details.value}</span>
                            ) : (
                              <span className="text-rose-500/80 italic font-mono font-medium">Missing / Not Configured</span>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-xs text-slate-400 font-semibold bg-slate-950 px-2.5 py-1 rounded-md border border-slate-800 font-mono">
                            {details.score_contribution}/{details.max_score} pts
                          </span>
                          <div className="p-1 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-400">
                            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                          </div>
                        </div>
                      </button>

                      {/* Expandable Body */}
                      {isExpanded && (
                        <div className="border-t border-slate-800/80 bg-slate-950/50 p-5 space-y-5 animate-slideDown">
                          
                          {/* Explanations */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                            <div className="bg-slate-900/40 p-3.5 rounded-xl border border-slate-800/80">
                              <h4 className="font-bold text-slate-200 mb-1.5 flex items-center gap-1.5 uppercase tracking-wide text-[10px] text-indigo-400">
                                <Info size={12} /> What is this?
                              </h4>
                              <p className="text-slate-300 leading-relaxed font-normal">
                                {details.beginner_explanation}
                              </p>
                            </div>
                            <div className="bg-slate-900/40 p-3.5 rounded-xl border border-slate-800/80">
                              <h4 className="font-bold text-slate-200 mb-1.5 flex items-center gap-1.5 uppercase tracking-wide text-[10px] text-rose-400">
                                <ShieldAlert size={12} /> Security Threat
                              </h4>
                              <p className="text-slate-300 leading-relaxed font-normal">
                                {details.security_impact}
                              </p>
                            </div>
                          </div>

                          {/* Real-World Threat Example */}
                          <div className="text-xs border-l-2 border-indigo-500/40 pl-3">
                            <h4 className="font-bold text-slate-300 mb-1">
                              Threat Scenario (Real-world Attack):
                            </h4>
                            <p className="text-slate-400 italic font-normal">
                              "{details.real_world_example}"
                            </p>
                          </div>

                          {/* Exam Tip Callout Box */}
                          <div className="bg-indigo-950/10 border border-indigo-850/40 rounded-xl p-3.5 flex gap-3 text-xs">
                            <div className="text-indigo-400 mt-0.5 shrink-0">
                              <GraduationCap size={18} />
                            </div>
                            <div>
                              <h5 className="font-bold text-indigo-300 uppercase tracking-wide text-[10px]">
                                CompTIA Security+ SY0-701 Exam Reference
                              </h5>
                              <p className="text-slate-300 mt-1 leading-relaxed font-normal">
                                {details.exam_tip}
                              </p>
                            </div>
                          </div>

                          {/* Recommendation config to fix */}
                          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
                            <div className="flex items-center justify-between mb-2">
                              <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-wide">
                                Recommendation (How to Fix)
                              </h5>
                              <button
                                onClick={() => copyToClipboard(details.recommendation, headerName)}
                                className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1 bg-slate-950 px-2 py-1 rounded border border-slate-800 transition-colors"
                              >
                                {copiedHeader === headerName ? (
                                  <>
                                    <Check size={10} className="text-emerald-400" />
                                    Copied!
                                  </>
                                ) : (
                                  <>
                                    <Copy size={10} />
                                    Copy Fix
                                  </>
                                )}
                              </button>
                            </div>
                            <p className="text-xs text-slate-300 leading-relaxed mb-3">
                              {details.recommendation}
                            </p>
                            {/* Dummy Nginx or Server block for context */}
                            {details.status !== 'good' && (
                              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900 font-mono text-[10px] text-indigo-300 overflow-x-auto">
                                <code className="block select-all">
                                  {headerName === 'Content-Security-Policy' && "add_header Content-Security-Policy \"default-src 'self'\";"}
                                  {headerName === 'Strict-Transport-Security' && "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"}
                                  {headerName === 'X-Frame-Options' && "add_header X-Frame-Options \"SAMEORIGIN\" always;"}
                                  {headerName === 'X-Content-Type-Options' && "add_header X-Content-Type-Options \"nosniff\" always;"}
                                  {headerName === 'Referrer-Policy' && "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"}
                                  {headerName === 'Permissions-Policy' && "add_header Permissions-Policy \"camera=(), microphone=()\" always;"}
                                  {headerName === 'X-XSS-Protection' && "add_header X-XSS-Protection \"1; mode=block\" always;"}
                                  {headerName === 'Access-Control-Allow-Origin' && "add_header Access-Control-Allow-Origin \"https://yourdomain.com\" always;"}
                                </code>
                              </div>
                            )}
                          </div>

                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </section>

            {/* Quick Reference Cheatsheet for Exam Studying */}
            <section className="bg-slate-900/30 border border-slate-800 rounded-2xl p-6 mt-8">
              <h3 className="text-base font-bold text-white flex items-center gap-2 mb-4">
                <BookOpen size={18} className="text-indigo-400" />
                SY0-701 Secure Web Architecture Study Guide
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-300 leading-relaxed">
                <div className="space-y-2">
                  <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[10px] text-indigo-400">
                    Secure Web Protocols (Domain 3.0)
                  </h4>
                  <p>
                    <strong>HSTS</strong> secures the transport layer by eliminating HTTP redirects vulnerable to SSL stripping. By preloading HSTS, the browser refuses to load the domain over plaintext HTTP.
                  </p>
                </div>
                <div className="space-y-2">
                  <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[10px] text-indigo-400">
                    Client-Side Isolation (Domain 4.0)
                  </h4>
                  <p>
                    <strong>CSP</strong> acts as standard application defense-in-depth by declaring acceptable origins for scripts. This prevents reflected, stored, or DOM-based Cross-Site Scripting (XSS).
                  </p>
                </div>
                <div className="space-y-2">
                  <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[10px] text-indigo-400">
                    Access Controls & MIME (Domain 3.0)
                  </h4>
                  <p>
                    Configuring CORS correctly (avoiding wildcards <code>*</code> on APIs) prevents data leakages across origins. <code>nosniff</code> blocks MIME-sniffing exploits converting safe assets into scripts.
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}
        
        {/* If no scan has been executed yet */}
        {!report && !loading && (
          <section className="text-center py-20 bg-slate-900/10 border border-dashed border-slate-850 rounded-3xl mt-8">
            <Shield size={64} className="mx-auto text-slate-700 mb-4 stroke-1 animate-pulse" />
            <h3 className="text-lg font-semibold text-slate-300">Ready to Analyze</h3>
            <p className="text-xs sm:text-sm text-slate-500 max-w-md mx-auto mt-2">
              Enter any domain in the box above to perform a deep inspection of its server security configurations.
            </p>
          </section>
        )}

      </main>
    </div>
  )
}

export default App
