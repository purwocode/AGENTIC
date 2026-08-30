"""
Web API & Dashboard Module.

Provides:
- REST API for programmatic access
- Web UI dashboard
- Real-time scanning status
- Integration endpoints

For security research only - requires proper authorization.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse
import uuid

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    """Represents a scanning job."""
    job_id: str
    target: str
    status: str  # "pending", "running", "completed", "failed"
    progress: float  # 0-100
    created_at: datetime
    started_at: datetime = None
    completed_at: datetime = None
    results: dict = field(default_factory=dict)
    error: str = ""
    options: dict = field(default_factory=dict)


class ScanQueue:
    """Thread-safe scan job queue."""
    
    def __init__(self, max_concurrent: int = 3):
        self.jobs: dict[str, ScanJob] = {}
        self.pending: list[str] = []
        self.running: list[str] = []
        self.max_concurrent = max_concurrent
        self._lock = threading.Lock()
    
    def create_job(self, target: str, options: dict = None) -> ScanJob:
        """Create a new scan job."""
        job_id = str(uuid.uuid4())
        job = ScanJob(
            job_id=job_id,
            target=target,
            status="pending",
            progress=0,
            created_at=datetime.now(),
            options=options or {}
        )
        
        with self._lock:
            self.jobs[job_id] = job
            self.pending.append(job_id)
        
        return job
    
    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get job by ID."""
        return self.jobs.get(job_id)
    
    def update_job(
        self,
        job_id: str,
        status: str = None,
        progress: float = None,
        results: dict = None,
        error: str = None
    ):
        """Update job status."""
        with self._lock:
            if job_id not in self.jobs:
                return
            
            job = self.jobs[job_id]
            
            if status:
                job.status = status
                if status == "running" and not job.started_at:
                    job.started_at = datetime.now()
                    if job_id in self.pending:
                        self.pending.remove(job_id)
                    if job_id not in self.running:
                        self.running.append(job_id)
                elif status in ["completed", "failed"]:
                    job.completed_at = datetime.now()
                    if job_id in self.running:
                        self.running.remove(job_id)
            
            if progress is not None:
                job.progress = progress
            
            if results:
                job.results = results
            
            if error:
                job.error = error
    
    def get_next_job(self) -> Optional[ScanJob]:
        """Get next pending job if capacity available."""
        with self._lock:
            if len(self.running) >= self.max_concurrent:
                return None
            
            if not self.pending:
                return None
            
            job_id = self.pending[0]
            return self.jobs.get(job_id)
    
    def list_jobs(self, status: str = None) -> list[ScanJob]:
        """List all jobs, optionally filtered by status."""
        jobs = list(self.jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for REST API."""
    
    scan_queue: ScanQueue = None
    api_key: str = None
    scan_function: Callable = None
    
    def log_message(self, format: str, *args) -> None:
        """Override to use our logger."""
        logger.debug(f"API: {format % args}")
    
    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
    
    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({"error": message}, status)
    
    def _check_auth(self) -> bool:
        """Check API key authentication."""
        if not self.api_key:
            return True  # No auth required
        
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:] == self.api_key
        
        api_key = self.headers.get("X-API-Key", "")
        return api_key == self.api_key
    
    def _parse_body(self) -> dict:
        """Parse JSON body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        
        body = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {}
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        if not self._check_auth():
            return self._send_error("Unauthorized", 401)
        
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        query = parse_qs(parsed.query)
        
        # Route handling
        if path == "api/health":
            return self._send_json({"status": "ok", "timestamp": datetime.now().isoformat()})
        
        elif path == "api/jobs":
            status_filter = query.get("status", [None])[0]
            jobs = self.scan_queue.list_jobs(status_filter)
            return self._send_json({
                "jobs": [self._job_to_dict(j) for j in jobs],
                "total": len(jobs)
            })
        
        elif path.startswith("api/jobs/"):
            job_id = path.split("/")[-1]
            job = self.scan_queue.get_job(job_id)
            if not job:
                return self._send_error("Job not found", 404)
            return self._send_json(self._job_to_dict(job))
        
        elif path == "api/stats":
            jobs = self.scan_queue.list_jobs()
            return self._send_json({
                "total_jobs": len(jobs),
                "pending": len([j for j in jobs if j.status == "pending"]),
                "running": len([j for j in jobs if j.status == "running"]),
                "completed": len([j for j in jobs if j.status == "completed"]),
                "failed": len([j for j in jobs if j.status == "failed"])
            })
        
        elif path == "" or path == "dashboard":
            # Serve dashboard HTML
            return self._serve_dashboard()
        
        else:
            return self._send_error("Not found", 404)
    
    def do_POST(self):
        """Handle POST requests."""
        if not self._check_auth():
            return self._send_error("Unauthorized", 401)
        
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        body = self._parse_body()
        
        if path == "api/scan":
            # Start new scan
            target = body.get("target")
            if not target:
                return self._send_error("Target URL required")
            
            # Validate authorization keyword
            authorization = body.get("authorization", "")
            if not any(kw in authorization.lower() for kw in ["izin", "authorized", "pentest", "bug bounty"]):
                return self._send_error("Authorization keyword required", 403)
            
            options = {
                "verbose": body.get("verbose", False),
                "debate": body.get("debate", False),
                "authorization": authorization
            }
            
            job = self.scan_queue.create_job(target, options)
            
            # Start scan in background
            threading.Thread(
                target=self._run_scan,
                args=(job.job_id,),
                daemon=True
            ).start()
            
            return self._send_json({
                "job_id": job.job_id,
                "status": "pending",
                "message": "Scan job created"
            }, 201)
        
        elif path == "api/validate":
            # Validate target
            target = body.get("target")
            if not target:
                return self._send_error("Target URL required")
            
            # Basic validation
            try:
                parsed_url = urlparse(target)
                if not parsed_url.scheme or not parsed_url.netloc:
                    return self._send_json({"valid": False, "error": "Invalid URL format"})
                
                return self._send_json({
                    "valid": True,
                    "scheme": parsed_url.scheme,
                    "host": parsed_url.netloc,
                    "path": parsed_url.path or "/"
                })
            except Exception as e:
                return self._send_json({"valid": False, "error": str(e)})
        
        else:
            return self._send_error("Not found", 404)
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        if not self._check_auth():
            return self._send_error("Unauthorized", 401)
        
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        
        if path.startswith("api/jobs/"):
            job_id = path.split("/")[-1]
            job = self.scan_queue.get_job(job_id)
            if not job:
                return self._send_error("Job not found", 404)
            
            if job.status == "running":
                return self._send_error("Cannot delete running job", 400)
            
            del self.scan_queue.jobs[job_id]
            return self._send_json({"message": "Job deleted"})
        
        return self._send_error("Not found", 404)
    
    def _job_to_dict(self, job: ScanJob) -> dict:
        """Convert job to dictionary."""
        return {
            "job_id": job.job_id,
            "target": job.target,
            "status": job.status,
            "progress": job.progress,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "results": job.results,
            "error": job.error,
            "options": job.options
        }
    
    def _run_scan(self, job_id: str):
        """Run scan in background."""
        job = self.scan_queue.get_job(job_id)
        if not job:
            return
        
        self.scan_queue.update_job(job_id, status="running", progress=0)
        
        try:
            # This would call the actual scanner
            if self.scan_function:
                results = self.scan_function(
                    target=job.target,
                    options=job.options,
                    progress_callback=lambda p: self.scan_queue.update_job(job_id, progress=p)
                )
                self.scan_queue.update_job(job_id, status="completed", progress=100, results=results)
            else:
                # Simulate scan for demo
                for i in range(10):
                    time.sleep(1)
                    self.scan_queue.update_job(job_id, progress=i * 10)
                
                self.scan_queue.update_job(
                    job_id,
                    status="completed",
                    progress=100,
                    results={"message": "Scan completed", "findings": []}
                )
        
        except Exception as e:
            self.scan_queue.update_job(job_id, status="failed", error=str(e))
    
    def _serve_dashboard(self):
        """Serve the web dashboard."""
        html = DASHBOARD_HTML
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())


DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Framework - Dashboard</title>
    <style>
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --accent: #00ff88;
            --accent-dim: #00aa5a;
            --text: #e0e0e0;
            --text-dim: #808080;
            --danger: #ff4444;
            --warning: #ffaa00;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid #222;
            margin-bottom: 30px;
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        
        .logo span { color: var(--text); }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #222;
        }
        
        .stat-card h3 {
            font-size: 2.5rem;
            color: var(--accent);
            margin-bottom: 5px;
        }
        
        .stat-card p { color: var(--text-dim); }
        
        .section {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid #222;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .section h2 {
            margin-bottom: 20px;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .new-scan-form {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 15px;
        }
        
        input, textarea, select, button {
            font-family: inherit;
            font-size: 1rem;
        }
        
        input[type="text"], textarea {
            background: var(--bg-dark);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 12px 15px;
            color: var(--text);
            width: 100%;
        }
        
        input:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        button {
            background: var(--accent);
            color: var(--bg-dark);
            border: none;
            border-radius: 8px;
            padding: 12px 25px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.2s;
        }
        
        button:hover { background: var(--accent-dim); }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .jobs-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .jobs-table th, .jobs-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #222;
        }
        
        .jobs-table th {
            color: var(--text-dim);
            font-weight: 500;
        }
        
        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .status-pending { background: #333; color: #888; }
        .status-running { background: #1a3a2a; color: var(--accent); }
        .status-completed { background: #1a3a1a; color: #4caf50; }
        .status-failed { background: #3a1a1a; color: var(--danger); }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: #222;
            border-radius: 3px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s;
        }
        
        .empty-state {
            text-align: center;
            padding: 50px;
            color: var(--text-dim);
        }
        
        .terminal {
            background: #000;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .terminal .line { margin: 2px 0; }
        .terminal .success { color: var(--accent); }
        .terminal .error { color: var(--danger); }
        .terminal .warning { color: var(--warning); }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .running .status-badge { animation: pulse 1.5s infinite; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">Attack<span>Surface</span></div>
            <div id="status">Connecting...</div>
        </header>
        
        <div class="stats" id="stats">
            <div class="stat-card">
                <h3 id="total-jobs">0</h3>
                <p>Total Scans</p>
            </div>
            <div class="stat-card">
                <h3 id="running-jobs">0</h3>
                <p>Running</p>
            </div>
            <div class="stat-card">
                <h3 id="completed-jobs">0</h3>
                <p>Completed</p>
            </div>
            <div class="stat-card">
                <h3 id="total-findings">0</h3>
                <p>Findings</p>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 New Scan</h2>
            <div class="new-scan-form">
                <div>
                    <input type="text" id="target" placeholder="https://target.com">
                    <input type="text" id="auth" placeholder="Authorization (e.g., 'dengan izin tertulis')" style="margin-top: 10px;">
                </div>
                <button onclick="startScan()">Start Scan</button>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Scan Jobs</h2>
            <table class="jobs-table">
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Progress</th>
                        <th>Created</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody id="jobs-list">
                    <tr class="empty-state">
                        <td colspan="5">No scans yet. Start a new scan above.</td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📟 Activity Log</h2>
            <div class="terminal" id="terminal">
                <div class="line">Welcome to Attack Surface Framework Dashboard</div>
                <div class="line">Ready for security research...</div>
            </div>
        </div>
    </div>
    
    <script>
        const API_BASE = window.location.origin + '/api';
        
        async function fetchStats() {
            try {
                const res = await fetch(API_BASE + '/stats');
                const data = await res.json();
                document.getElementById('total-jobs').textContent = data.total_jobs;
                document.getElementById('running-jobs').textContent = data.running;
                document.getElementById('completed-jobs').textContent = data.completed;
                document.getElementById('status').textContent = 'Connected';
                document.getElementById('status').style.color = '#00ff88';
            } catch (e) {
                document.getElementById('status').textContent = 'Disconnected';
                document.getElementById('status').style.color = '#ff4444';
            }
        }
        
        async function fetchJobs() {
            try {
                const res = await fetch(API_BASE + '/jobs');
                const data = await res.json();
                
                const tbody = document.getElementById('jobs-list');
                
                if (data.jobs.length === 0) {
                    tbody.innerHTML = '<tr class="empty-state"><td colspan="5">No scans yet. Start a new scan above.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.jobs.map(job => `
                    <tr class="${job.status}">
                        <td><code>${job.target}</code></td>
                        <td><span class="status-badge status-${job.status}">${job.status}</span></td>
                        <td>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${job.progress}%"></div>
                            </div>
                        </td>
                        <td>${new Date(job.created_at).toLocaleString()}</td>
                        <td>${(job.results?.findings || []).length || '-'}</td>
                    </tr>
                `).join('');
                
                // Update findings count
                let totalFindings = 0;
                data.jobs.forEach(j => {
                    if (j.results?.findings) totalFindings += j.results.findings.length;
                });
                document.getElementById('total-findings').textContent = totalFindings;
                
            } catch (e) {
                console.error('Failed to fetch jobs:', e);
            }
        }
        
        async function startScan() {
            const target = document.getElementById('target').value.trim();
            const auth = document.getElementById('auth').value.trim();
            
            if (!target) {
                log('Error: Target URL required', 'error');
                return;
            }
            
            if (!auth) {
                log('Error: Authorization keyword required', 'error');
                return;
            }
            
            try {
                const res = await fetch(API_BASE + '/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, authorization: auth })
                });
                
                const data = await res.json();
                
                if (data.error) {
                    log('Error: ' + data.error, 'error');
                } else {
                    log('Scan started: ' + data.job_id, 'success');
                    document.getElementById('target').value = '';
                    document.getElementById('auth').value = '';
                    fetchJobs();
                }
            } catch (e) {
                log('Error: ' + e.message, 'error');
            }
        }
        
        function log(message, type = '') {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'line ' + type;
            line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Initial load
        fetchStats();
        fetchJobs();
        
        // Refresh periodically
        setInterval(fetchStats, 5000);
        setInterval(fetchJobs, 3000);
    </script>
</body>
</html>'''


class APIServer:
    """
    REST API and Web Dashboard Server.
    
    Features:
    - REST API for scan management
    - Web dashboard for monitoring
    - Authentication support
    - CORS handling
    
    Usage:
        server = APIServer(port=8080, api_key="your-secret-key")
        server.start()
        
        # API endpoints:
        # GET  /api/health - Health check
        # GET  /api/stats - Scan statistics
        # GET  /api/jobs - List all jobs
        # GET  /api/jobs/{id} - Get job details
        # POST /api/scan - Start new scan
        # DELETE /api/jobs/{id} - Delete job
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        api_key: str = None,
        max_concurrent_scans: int = 3,
        scan_function: Callable = None
    ):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.scan_queue = ScanQueue(max_concurrent=max_concurrent_scans)
        self.scan_function = scan_function
        
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self) -> bool:
        """Start the API server."""
        if self._running:
            logger.warning("API server already running")
            return False
        
        try:
            # Configure handler
            APIHandler.scan_queue = self.scan_queue
            APIHandler.api_key = self.api_key
            APIHandler.scan_function = self.scan_function
            
            # Create server
            self.server = HTTPServer((self.host, self.port), APIHandler)
            
            # Start in background thread
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            self._running = True
            
            logger.info(f"API server started on http://{self.host}:{self.port}")
            logger.info(f"Dashboard: http://{self.host}:{self.port}/dashboard")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            return False
    
    def _serve(self):
        """Server loop."""
        try:
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"API server error: {e}")
        finally:
            self._running = False
    
    def stop(self):
        """Stop the API server."""
        if self.server:
            self.server.shutdown()
            self._running = False
            logger.info("API server stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running
    
    def get_api_url(self) -> str:
        """Get API base URL."""
        return f"http://{self.host}:{self.port}/api"
    
    def get_dashboard_url(self) -> str:
        """Get dashboard URL."""
        return f"http://{self.host}:{self.port}/dashboard"


class DistributedScanner:
    """
    Distributed scanning coordinator.
    
    Manages multiple scanner workers for parallel scanning.
    """
    
    def __init__(self, workers: list[str] = None):
        """
        Initialize distributed scanner.
        
        Args:
            workers: List of worker URLs (e.g., ["http://worker1:8080", "http://worker2:8080"])
        """
        self.workers = workers or []
        self.worker_status: dict[str, dict] = {}
        self.job_assignments: dict[str, str] = {}  # job_id -> worker_url
    
    def add_worker(self, worker_url: str):
        """Add a worker node."""
        self.workers.append(worker_url)
        self.worker_status[worker_url] = {"status": "unknown", "last_check": None}
    
    def remove_worker(self, worker_url: str):
        """Remove a worker node."""
        if worker_url in self.workers:
            self.workers.remove(worker_url)
        if worker_url in self.worker_status:
            del self.worker_status[worker_url]
    
    async def check_workers(self) -> dict[str, bool]:
        """Check health of all workers."""
        results = {}
        for worker in self.workers:
            try:
                # Would make actual health check request
                results[worker] = True
                self.worker_status[worker] = {
                    "status": "healthy",
                    "last_check": datetime.now().isoformat()
                }
            except Exception:
                results[worker] = False
                self.worker_status[worker] = {
                    "status": "unhealthy",
                    "last_check": datetime.now().isoformat()
                }
        return results
    
    def get_available_worker(self) -> Optional[str]:
        """Get an available worker for a new job."""
        for worker, status in self.worker_status.items():
            if status.get("status") == "healthy":
                return worker
        return None
    
    async def distribute_scan(
        self,
        targets: list[str],
        options: dict = None
    ) -> dict[str, str]:
        """
        Distribute scans across workers.
        
        Returns mapping of target -> job_id
        """
        job_ids = {}
        
        for target in targets:
            worker = self.get_available_worker()
            if not worker:
                logger.warning(f"No available worker for {target}")
                continue
            
            # Would submit job to worker
            job_id = str(uuid.uuid4())
            job_ids[target] = job_id
            self.job_assignments[job_id] = worker
        
        return job_ids
    
    def get_stats(self) -> dict:
        """Get distributed scanner statistics."""
        return {
            "total_workers": len(self.workers),
            "healthy_workers": sum(1 for s in self.worker_status.values() if s.get("status") == "healthy"),
            "active_jobs": len(self.job_assignments),
            "workers": self.worker_status
        }


class VulnerabilityDatabase:
    """
    Local vulnerability database for reference.
    
    Stores known vulnerabilities and patterns.
    """
    
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or Path("./vuln_db.json")
        self.vulnerabilities: dict[str, dict] = {}
        self._load()
    
    def _load(self):
        """Load database from file."""
        if self.db_path.exists():
            try:
                self.vulnerabilities = json.loads(self.db_path.read_text())
            except Exception as e:
                logger.error(f"Failed to load vuln DB: {e}")
    
    def _save(self):
        """Save database to file."""
        try:
            self.db_path.write_text(json.dumps(self.vulnerabilities, indent=2, default=str))
        except Exception as e:
            logger.error(f"Failed to save vuln DB: {e}")
    
    def add_vulnerability(
        self,
        vuln_id: str,
        vuln_type: str,
        target: str,
        payload: str,
        evidence: str,
        cvss_score: float = None,
        tags: list[str] = None
    ):
        """Add vulnerability to database."""
        self.vulnerabilities[vuln_id] = {
            "vuln_type": vuln_type,
            "target": target,
            "payload": payload,
            "evidence": evidence,
            "cvss_score": cvss_score,
            "tags": tags or [],
            "added_at": datetime.now().isoformat()
        }
        self._save()
    
    def search(
        self,
        vuln_type: str = None,
        target: str = None,
        tags: list[str] = None
    ) -> list[dict]:
        """Search vulnerabilities."""
        results = []
        
        for vuln_id, vuln in self.vulnerabilities.items():
            if vuln_type and vuln_type.lower() not in vuln.get("vuln_type", "").lower():
                continue
            if target and target.lower() not in vuln.get("target", "").lower():
                continue
            if tags and not any(t in vuln.get("tags", []) for t in tags):
                continue
            
            results.append({"id": vuln_id, **vuln})
        
        return results
    
    def get_stats(self) -> dict:
        """Get database statistics."""
        types = {}
        for vuln in self.vulnerabilities.values():
            vtype = vuln.get("vuln_type", "unknown")
            types[vtype] = types.get(vtype, 0) + 1
        
        return {
            "total": len(self.vulnerabilities),
            "by_type": types
        }


class ComplianceChecker:
    """
    Compliance checking against security standards.
    
    Supports OWASP Top 10, PCI-DSS, etc.
    """
    
    OWASP_TOP_10_2021 = {
        "A01": {
            "name": "Broken Access Control",
            "related_vulns": ["idor", "auth_bypass", "privilege_escalation", "path_traversal"]
        },
        "A02": {
            "name": "Cryptographic Failures",
            "related_vulns": ["sensitive_data_exposure", "weak_crypto", "insecure_storage"]
        },
        "A03": {
            "name": "Injection",
            "related_vulns": ["sqli", "nosqli", "xss", "command_injection", "ssti", "xxe", "ldap_injection"]
        },
        "A04": {
            "name": "Insecure Design",
            "related_vulns": ["business_logic", "rate_limiting", "missing_validation"]
        },
        "A05": {
            "name": "Security Misconfiguration",
            "related_vulns": ["default_credentials", "debug_enabled", "excessive_permissions", "missing_headers"]
        },
        "A06": {
            "name": "Vulnerable and Outdated Components",
            "related_vulns": ["outdated_software", "known_cve", "unpatched"]
        },
        "A07": {
            "name": "Identification and Authentication Failures",
            "related_vulns": ["weak_password", "session_fixation", "credential_stuffing", "brute_force"]
        },
        "A08": {
            "name": "Software and Data Integrity Failures",
            "related_vulns": ["deserialization", "ci_cd_issues", "update_integrity"]
        },
        "A09": {
            "name": "Security Logging and Monitoring Failures",
            "related_vulns": ["insufficient_logging", "no_monitoring", "log_injection"]
        },
        "A10": {
            "name": "Server-Side Request Forgery",
            "related_vulns": ["ssrf", "url_redirection"]
        }
    }
    
    @classmethod
    def check_owasp(cls, findings: list[dict]) -> dict:
        """
        Check findings against OWASP Top 10.
        
        Returns compliance report.
        """
        report = {
            "standard": "OWASP Top 10 2021",
            "findings_mapped": 0,
            "categories_affected": [],
            "details": {}
        }
        
        vuln_types = [f.get("vuln_type", "").lower() for f in findings]
        
        for cat_id, cat_info in cls.OWASP_TOP_10_2021.items():
            matched = []
            for vuln in vuln_types:
                for related in cat_info["related_vulns"]:
                    if related in vuln or vuln in related:
                        matched.append(vuln)
                        break
            
            if matched:
                report["categories_affected"].append(cat_id)
                report["details"][cat_id] = {
                    "name": cat_info["name"],
                    "matched_vulns": list(set(matched)),
                    "count": len(matched)
                }
                report["findings_mapped"] += len(matched)
        
        return report
    
    @classmethod
    def generate_compliance_report(
        cls,
        findings: list[dict],
        standards: list[str] = None
    ) -> dict:
        """Generate comprehensive compliance report."""
        standards = standards or ["owasp"]
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "compliance_checks": {}
        }
        
        if "owasp" in standards:
            report["compliance_checks"]["owasp"] = cls.check_owasp(findings)
        
        return report


# Export classes
__all__ = [
    "ScanJob",
    "ScanQueue",
    "APIHandler",
    "APIServer",
    "DistributedScanner",
    "VulnerabilityDatabase",
    "ComplianceChecker",
]
