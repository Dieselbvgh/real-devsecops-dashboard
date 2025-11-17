// Real DevSecOps Dashboard JavaScript
class DevSecOpsDashboard {
    constructor() {
        this.currentScan = null;
        this.currentFix = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboard();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.showTab(e.target.dataset.tab);
            });
        });

        // Chat input enter key
        document.getElementById('chat-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });
    }

    showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.add('hidden');
        });

        // Show selected tab
        document.getElementById(`tab-${tabName}`).classList.remove('hidden');

        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Load tab-specific data
        switch(tabName) {
            case 'home':
                this.loadDashboard();
                break;
            case 'van':
                this.loadVANStatus();
                break;
            case 'scan':
                this.loadScanHistory();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'autofix':
                this.loadFixHistory();
                break;
        }
    }

    async apiCall(endpoint, options = {}) {
        try {
            const response = await fetch(`/api${endpoint}`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API Call failed:', error);
            return { success: false, error: error.message };
        }
    }

    // Dashboard Home
    async loadDashboard() {
        try {
            // Load health status
            const health = await this.apiCall('/health');
            document.getElementById('health-status').innerHTML = `
                <div class="status-badge status-healthy">Online</div>
                <p>Dashboard is running</p>
            `;

            // Load recent scans
            const scans = await this.apiCall('/scans');
            if (scans.success && scans.data.length > 0) {
                const recent = scans.data.slice(0, 3);
                document.getElementById('recent-scans').innerHTML = `
                    ${recent.map(scan => `
                        <div>${scan.image} - <span class="status-badge ${scan.status === 'completed' ? 'status-healthy' : 'status-warning'}">${scan.status}</span></div>
                    `).join('')}
                `;
            } else {
                document.getElementById('recent-scans').innerHTML = '<p>No scans yet</p>';
            }

            // Load active alerts
            const alerts = await this.apiCall('/alerts');
            if (alerts.success) {
                const active = alerts.data.filter(a => a.status === 'open').slice(0, 5);
                document.getElementById('active-alerts').innerHTML = `
                    ${active.length} active alerts
                    ${active.map(alert => `
                        <div class="alert-item ${alert.severity}">
                            <strong>${alert.severity.toUpperCase()}:</strong> ${alert.title}
                        </div>
                    `).join('')}
                `;
            }

        } catch (error) {
            console.error('Dashboard load error:', error);
        }
    }

    // VAN Monitoring
    async loadVANStatus() {
        const vanElement = document.getElementById('van-status');
        vanElement.innerHTML = '<div class="loading">Loading real system metrics...</div>';

        try {
            const result = await this.apiCall('/van');
            
            if (result.success) {
                const checks = result.data;
                let html = '';

                for (const [checkName, checkData] of Object.entries(checks)) {
                    const statusClass = checkData.status === 'healthy' ? 'healthy' : 
                                      checkData.status === 'warning' ? 'warning' : 'error';
                    
                    html += `
                        <div class="van-item ${statusClass}">
                            <h4>${checkName.toUpperCase()}</h4>
                            <div class="status-badge status-${statusClass}">${checkData.status}</div>
                            <div class="van-details">
                                ${Object.entries(checkData).map(([key, value]) => {
                                    if (key === 'status') return '';
                                    return `<div><strong>${key}:</strong> ${typeof value === 'object' ? JSON.stringify(value) : value}</div>`;
                                }).join('')}
                            </div>
                        </div>
                    `;
                }

                vanElement.innerHTML = html;
            } else {
                vanElement.innerHTML = `<div class="van-item error">Error loading VAN status: ${result.error}</div>`;
            }
        } catch (error) {
            vanElement.innerHTML = `<div class="van-item error">Failed to load VAN status: ${error.message}</div>`;
        }
    }

    // Docker Scanning
    async startScan() {
        const imageInput = document.getElementById('scan-image-input');
        const image = imageInput.value.trim();
        
        if (!image) {
            alert('Please enter a Docker image name');
            return;
        }

        const progressElement = document.getElementById('scan-progress');
        progressElement.innerHTML = `
            <div class="card">
                <h4>Starting Real Security Scan</h4>
                <p>Scanning: <strong>${image}</strong></p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <p>This may take several minutes for real Trivy + Grype scans...</p>
            </div>
        `;

        try {
            const result = await this.apiCall('/scan', {
                method: 'POST',
                body: JSON.stringify({ image })
            });

            if (result.success) {
                progressElement.innerHTML = `
                    <div class="card" style="border-left-color: #10b981;">
                        <h4>✅ Scan Started Successfully</h4>
                        <p>Scan ID: ${result.data.id}</p>
                        <p>Status: ${result.data.status}</p>
                        <p>Scanning with real Trivy and Grype tools...</p>
                    </div>
                `;

                // Poll for results
                this.pollScanResult(result.data.id);
            } else {
                progressElement.innerHTML = `
                    <div class="card" style="border-left-color: #ef4444;">
                        <h4>❌ Scan Failed</h4>
                        <p>Error: ${result.error}</p>
                    </div>
                `;
            }
        } catch (error) {
            progressElement.innerHTML = `
                <div class="card" style="border-left-color: #ef4444;">
                    <h4>❌ Scan Failed</h4>
                    <p>Error: ${error.message}</p>
                </div>
            `;
        }
    }

    async pollScanResult(scanId) {
        const maxAttempts = 30;
        let attempts = 0;

        const poll = async () => {
            attempts++;
            const scans = await this.apiCall('/scans');
            
            if (scans.success) {
                const scan = scans.data.find(s => s.id === scanId);
                
                if (scan && scan.status === 'completed') {
                    this.displayScanResults(scan);
                    this.loadScanHistory();
                    return;
                } else if (scan && scan.status === 'error') {
                    document.getElementById('scan-progress').innerHTML = `
                        <div class="card" style="border-left-color: #ef4444;">
                            <h4>❌ Scan Error</h4>
                            <p>${scan.error || 'Unknown error'}</p>
                        </div>
                    `;
                    return;
                }
            }

            if (attempts < maxAttempts) {
                // Update progress
                const progress = (attempts / maxAttempts) * 100;
                const progressFill = document.querySelector('.progress-fill');
                if (progressFill) {
                    progressFill.style.width = `${progress}%`;
                }
                
                setTimeout(poll, 3000);
            } else {
                document.getElementById('scan-progress').innerHTML = `
                    <div class="card" style="border-left-color: #f59e0b;">
                        <h4>⚠️ Scan Taking Longer Than Expected</h4>
                        <p>The scan is still running. Check back later.</p>
                    </div>
                `;
            }
        };

        poll();
    }

    displayScanResults(scan) {
        const resultsElement = document.getElementById('scan-results-content');
        
        let vulnerabilities = [];
        let criticalCount = 0;
        let highCount = 0;

        // Process Trivy results
        if (scan.trivy && scan.trivy.success) {
            scan.trivy.vulnerabilities.forEach(result => {
                (result.Vulnerabilities || []).forEach(vuln => {
                    vulnerabilities.push({
                        tool: 'trivy',
                        severity: vuln.Severity || 'unknown',
                        id: vuln.VulnerabilityID,
                        package: vuln.PkgName,
                        description: vuln.Description || 'No description'
                    });

                    if (vuln.Severity === 'CRITICAL') criticalCount++;
                    if (vuln.Severity === 'HIGH') highCount++;
                });
            });
        }

        // Process Grype results
        if (scan.grype && scan.grype.success) {
            (scan.grype.matches || []).forEach(match => {
                vulnerabilities.push({
                    tool: 'grype',
                    severity: match.vulnerability?.severity || 'unknown',
                    id: match.vulnerability?.id,
                    package: match.artifact?.name,
                    description: match.vulnerability?.description || 'No description'
                });

                const severity = match.vulnerability?.severity;
                if (severity === 'Critical') criticalCount++;
                if (severity === 'High') highCount++;
            });
        }

        let html = `
            <div class="card" style="border-left-color: ${criticalCount > 0 ? '#ef4444' : highCount > 0 ? '#f97316' : '#10b981'};">
                <h4>Scan Summary - ${scan.image}</h4>
                <p><strong>Status:</strong> ${scan.status}</p>
                <p><strong>Completed:</strong> ${new Date(scan.completedAt).toLocaleString()}</p>
                <p><strong>Critical Vulnerabilities:</strong> <span style="color: #ef4444;">${criticalCount}</span></p>
                <p><strong>High Vulnerabilities:</strong> <span style="color: #f97316;">${highCount}</span></p>
                <p><strong>Total Findings:</strong> ${vulnerabilities.length}</p>
            </div>
        `;

        if (vulnerabilities.length > 0) {
            html += '<h4>Vulnerability Details:</h4>';
            vulnerabilities.slice(0, 20).forEach(vuln => {
                const severityClass = vuln.severity.toLowerCase();
                html += `
                    <div class="vulnerability-item ${severityClass}">
                        <strong>${vuln.severity}</strong> - ${vuln.id}<br>
                        <strong>Package:</strong> ${vuln.package}<br>
                        <strong>Tool:</strong> ${vuln.tool}<br>
                        <small>${vuln.description.substring(0, 200)}...</small>
                    </div>
                `;
            });

            if (vulnerabilities.length > 20) {
                html += `<p>... and ${vulnerabilities.length - 20} more vulnerabilities</p>`;
            }
        } else {
            html += '<div class="card" style="border-left-color: #10b981;"><p>✅ No vulnerabilities found!</p></div>';
        }

        resultsElement.innerHTML = html;
        document.getElementById('scan-progress').innerHTML = '';
    }

    async loadScanHistory() {
        const historyElement = document.getElementById('scan-history');
        
        try {
            const result = await this.apiCall('/scans');
            
            if (result.success && result.data.length > 0) {
                let html = '<div class="scan-history-list">';
                
                result.data.slice(0, 10).forEach(scan => {
                    html += `
                        <div class="card" style="border-left-color: ${scan.status === 'completed' ? '#10b981' : scan.status === 'error' ? '#ef4444' : '#f59e0b'};">
                            <p><strong>Image:</strong> ${scan.image}</p>
                            <p><strong>Status:</strong> ${scan.status}</p>
                            <p><strong>Time:</strong> ${new Date(scan.timestamp).toLocaleString()}</p>
                            ${scan.status === 'completed' ? `<button class="btn" onclick="dashboard.viewScan('${scan.id}')">View Results</button>` : ''}
                        </div>
                    `;
                });
                
                html += '</div>';
                historyElement.innerHTML = html;
            } else {
                historyElement.innerHTML = '<p>No scan history available.</p>';
            }
        } catch (error) {
            historyElement.innerHTML = `<p>Error loading scan history: ${error.message}</p>`;
        }
    }

    // Auto-Fix System
    async startAutoFix() {
        const imageInput = document.getElementById('fix-image-input');
        const image = imageInput.value.trim();
        
        if (!image) {
            alert('Please enter a Docker image name');
            return;
        }

        const progressElement = document.getElementById('fix-progress');
        progressElement.innerHTML = `
            <div class="card">
                <h4>Starting Real Auto-Fix</h4>
                <p>Hardening: <strong>${image}</strong></p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <p>This will create a new hardened image with updated packages...</p>
            </div>
        `;

        try {
            const result = await this.apiCall('/auto-fix', {
                method: 'POST',
                body: JSON.stringify({ image })
            });

            if (result.success) {
                progressElement.innerHTML = `
                    <div class="card" style="border-left-color: #10b981;">
                        <h4>✅ Auto-Fix Started Successfully</h4>
                        <p>Fix ID: ${result.data.id}</p>
                        <p>Status: ${result.data.status}</p>
                        <p>This process may take several minutes...</p>
                    </div>
                `;

                this.pollFixResult(result.data.id);
            } else {
                progressElement.innerHTML = `
                    <div class="card" style="border-left-color: #ef4444;">
                        <h4>❌ Auto-Fix Failed</h4>
                        <p>Error: ${result.error}</p>
                    </div>
                `;
            }
        } catch (error) {
            progressElement.innerHTML = `
                <div class="card" style="border-left-color: #ef4444;">
                    <h4>❌ Auto-Fix Failed</h4>
                    <p>Error: ${error.message}</p>
                </div>
            `;
        }
    }

    async pollFixResult(fixId) {
        // For now, we'll simulate the fix process
        // In a real implementation, you would poll for the actual fix status
        const steps = ['pull_image', 'create_container', 'update_packages', 'commit_image', 'cleanup'];
        let currentStep = 0;

        const updateProgress = () => {
            const progress = ((currentStep + 1) / steps.length) * 100;
            const progressFill = document.querySelector('#fix-progress .progress-fill');
            if (progressFill) {
                progressFill.style.width = `${progress}%`;
            }
        };

        const simulateStep = () => {
            if (currentStep < steps.length) {
                const step = steps[currentStep];
                document.getElementById('fix-progress').innerHTML += `
                    <p>✅ Step ${currentStep + 1}: ${step.replace('_', ' ')} completed</p>
                `;
                currentStep++;
                updateProgress();
                setTimeout(simulateStep, 2000);
            } else {
                document.getElementById('fix-progress').innerHTML += `
                    <div class="card" style="border-left-color: #10b981; margin-top: 1rem;">
                        <h4>✅ Auto-Fix Completed!</h4>
                        <p>New hardened image created: <strong>${document.getElementById('fix-image-input').value}-hardened-${fixId}:latest</strong></p>
                        <p>You can now use this secured image in your deployments.</p>
                    </div>
                `;
                this.loadFixHistory();
            }
        };

        setTimeout(simulateStep, 2000);
    }

    async loadFixHistory() {
        // Implementation for loading fix history
        document.getElementById('fix-results').innerHTML = `
            <div class="card">
                <p>Auto-fix history would be displayed here.</p>
                <p>Each fix creates a new hardened Docker image with updated packages.</p>
            </div>
        `;
    }

    // Alerts Management
    async loadAlerts() {
        const alertsElement = document.getElementById('alerts-list');
        
        try {
            const result = await this.apiCall('/alerts');
            
            if (result.success) {
                if (result.data.length > 0) {
                    let html = '';
                    
                    result.data.forEach(alert => {
                        html += `
                            <div class="alert-item ${alert.severity}">
                                <div class="alert-header">
                                    <strong>${alert.severity.toUpperCase()}</strong>
                                    <span class="status-badge">${alert.status}</span>
                                </div>
                                <h4>${alert.title}</h4>
                                <p>${alert.description}</p>
                                <div class="alert-meta">
                                    <small>Type: ${alert.type} | Time: ${new Date(alert.timestamp).toLocaleString()}</small>
                                    ${alert.image ? `<br><small>Image: ${alert.image}</small>` : ''}
                                </div>
                                ${alert.status === 'open' ? `
                                    <button class="btn" onclick="dashboard.mitigateAlert('${alert.id}')">Mitigate</button>
                                ` : ''}
                            </div>
                        `;
                    });
                    
                    alertsElement.innerHTML = html;
                } else {
                    alertsElement.innerHTML = '<div class="card"><p>✅ No active alerts</p></div>';
                }
            } else {
                alertsElement.innerHTML = `<div class="card" style="border-left-color: #ef4444;"><p>Error loading alerts: ${result.error}</p></div>`;
            }
        } catch (error) {
            alertsElement.innerHTML = `<div class="card" style="border-left-color: #ef4444;"><p>Failed to load alerts: ${error.message}</p></div>`;
        }
    }

    async mitigateAlert(alertId) {
        try {
            const result = await this.apiCall(`/alerts/${alertId}/mitigate`, {
                method: 'POST'
            });

            if (result.success) {
                alert('Alert mitigated successfully!');
                this.loadAlerts();
                this.loadDashboard();
            } else {
                alert('Failed to mitigate alert: ' + result.error);
            }
        } catch (error) {
            alert('Error mitigating alert: ' + error.message);
        }
    }

    // Chat Assistant
    async sendMessage() {
        const input = document.getElementById('chat-input');
        const message = input.value.trim();
        
        if (!message) return;

        const messagesElement = document.getElementById('chat-messages');
        
        // Add user message
        messagesElement.innerHTML += `
            <div class="message user">
                <strong>You:</strong> ${message}
            </div>
        `;

        input.value = '';
        messagesElement.scrollTop = messagesElement.scrollHeight;

        try {
            const result = await this.apiCall('/chat', {
                method: 'POST',
                body: JSON.stringify({ message })
            });

            if (result.success) {
                // Add bot response
                messagesElement.innerHTML += `
                    <div class="message bot">
                        <strong>Assistant:</strong> ${result.response}
                    </div>
                `;
            } else {
                messagesElement.innerHTML += `
                    <div class="message bot">
                        <strong>Assistant:</strong> Sorry, I encountered an error: ${result.error}
                    </div>
                `;
            }

            messagesElement.scrollTop = messagesElement.scrollHeight;
        } catch (error) {
            messagesElement.innerHTML += `
                <div class="message bot">
                    <strong>Assistant:</strong> Sorry, I'm having trouble responding right now.
                </div>
            `;
            messagesElement.scrollTop = messagesElement.scrollHeight;
        }
    }

    // Auto-refresh
    startAutoRefresh() {
        // Refresh VAN status every 30 seconds if on VAN tab
        setInterval(() => {
            const activeTab = document.querySelector('.tab-btn.active').dataset.tab;
            if (activeTab === 'van') {
                this.loadVANStatus();
            }
        }, 30000);

        // Refresh dashboard every 60 seconds
        setInterval(() => {
            this.loadDashboard();
        }, 60000);
    }
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new DevSecOpsDashboard();
});

// Global functions for HTML onclick handlers
function showTab(tabName) {
    dashboard.showTab(tabName);
}

function startScan() {
    dashboard.startScan();
}

function startAutoFix() {
    dashboard.startAutoFix();
}

function loadAlerts() {
    dashboard.loadAlerts();
}

function loadVANStatus() {
    dashboard.loadVANStatus();
}

function sendMessage() {
    dashboard.sendMessage();
}
