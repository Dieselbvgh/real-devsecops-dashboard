/**
 * REAL DevSecOps Dashboard Server
 * Real Trivy + Grype scans + VAN monitoring + Auto-fix
 */

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 5001;
const DATA_DIR = path.join(__dirname, 'data');
const LOGS_DIR = path.join(__dirname, 'logs');
const SCAN_DIR = path.join(__dirname, 'scans');

// Create directories
[DATA_DIR, LOGS_DIR, SCAN_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Files paths
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
const VAN_CACHE_FILE = path.join(DATA_DIR, 'van_cache.json');

// Initialize files
if (!fs.existsSync(ALERTS_FILE)) fs.writeFileSync(ALERTS_FILE, '[]');

// Logging function
function log(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  console.log(logMessage.trim());
  fs.appendFileSync(path.join(LOGS_DIR, 'server.log'), logMessage);
}

// Utility functions
function safeExec(command, options = {}) {
  return new Promise((resolve) => {
    exec(command, { timeout: 300000, ...options }, (error, stdout, stderr) => {
      resolve({
        success: !error,
        error: error ? error.message : null,
        stdout: stdout || '',
        stderr: stderr || '',
        code: error ? error.code : 0
      });
    });
  });
}

// Alert system
function readAlerts() {
  try {
    return JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function writeAlerts(alerts) {
  fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2));
}

function createAlert(alert) {
  const alerts = readAlerts();
  const newAlert = {
    id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    status: 'open',
    ...alert
  };
  alerts.unshift(newAlert);
  writeAlerts(alerts);
  log(`ALERT: ${newAlert.severity} - ${newAlert.title}`);
  return newAlert;
}

// REAL VAN Monitoring
async function checkSystemHealth() {
  log('Running REAL VAN system checks...');
  
  const checks = {};
  
  // CPU Usage (REAL)
  try {
    const load = os.loadavg();
    const cores = os.cpus().length;
    const cpuUsage = (load[0] / cores * 100).toFixed(2);
    checks.cpu = {
      status: cpuUsage < 80 ? 'healthy' : 'warning',
      usage: cpuUsage + '%',
      load: load,
      cores: cores
    };
    if (cpuUsage >= 80) {
      createAlert({
        severity: 'high',
        title: 'High CPU Usage',
        description: `CPU usage at ${cpuUsage}%`,
        type: 'van-cpu'
      });
    }
  } catch (e) {
    checks.cpu = { status: 'error', error: e.message };
  }
  
  // Memory Usage (REAL)
  try {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memoryUsage = ((usedMem / totalMem) * 100).toFixed(2);
    checks.memory = {
      status: memoryUsage < 85 ? 'healthy' : 'warning',
      usage: memoryUsage + '%',
      total: (totalMem / 1024 / 1024 / 1024).toFixed(2) + 'GB',
      free: (freeMem / 1024 / 1024 / 1024).toFixed(2) + 'GB'
    };
    if (memoryUsage >= 85) {
      createAlert({
        severity: 'high',
        title: 'High Memory Usage',
        description: `Memory usage at ${memoryUsage}%`,
        type: 'van-memory'
      });
    }
  } catch (e) {
    checks.memory = { status: 'error', error: e.message };
  }
  
  // Disk Usage (REAL)
  try {
    const diskResult = await safeExec('df -h / | awk \'NR==2{print $5}\'');
    const usage = diskResult.stdout.trim().replace('%', '');
    checks.disk = {
      status: usage < 90 ? 'healthy' : 'warning',
      usage: usage + '%',
      raw: diskResult.stdout
    };
    if (usage >= 90) {
      createAlert({
        severity: 'high',
        title: 'High Disk Usage',
        description: `Disk usage at ${usage}%`,
        type: 'van-disk'
      });
    }
  } catch (e) {
    checks.disk = { status: 'error', error: e.message };
  }
  
  // Network Connections (REAL DDoS check)
  try {
    const netResult = await safeExec('netstat -an | grep ESTABLISHED | wc -l');
    const connections = parseInt(netResult.stdout.trim()) || 0;
    checks.network = {
      status: connections < 1000 ? 'healthy' : 'warning',
      connections: connections,
      description: 'ESTABLISHED connections'
    };
    if (connections >= 1000) {
      createAlert({
        severity: 'critical',
        title: 'Possible DDoS Attack',
        description: `${connections} established connections`,
        type: 'van-ddos'
      });
    }
  } catch (e) {
    checks.network = { status: 'error', error: e.message };
  }
  
  // UFW Firewall (REAL)
  try {
    const ufwResult = await safeExec('sudo ufw status 2>/dev/null || echo "inactive"');
    const isActive = ufwResult.stdout.toLowerCase().includes('active');
    checks.firewall = {
      status: isActive ? 'healthy' : 'warning',
      active: isActive,
      statusText: ufwResult.stdout.split('\n')[0] || 'unknown'
    };
    if (!isActive) {
      createAlert({
        severity: 'medium',
        title: 'Firewall Not Active',
        description: 'UFW firewall is not enabled',
        type: 'van-firewall'
      });
    }
  } catch (e) {
    checks.firewall = { status: 'error', error: e.message };
  }
  
  // Docker Status (REAL)
  try {
    const dockerResult = await safeExec('docker ps --format "table {{.Names}}\\t{{.Status}}"');
    checks.docker = {
      status: dockerResult.success ? 'healthy' : 'error',
      running: dockerResult.success,
      containers: dockerResult.stdout.split('\n').slice(1).filter(c => c.trim())
    };
    if (!dockerResult.success) {
      createAlert({
        severity: 'medium',
        title: 'Docker Not Running',
        description: 'Docker daemon may not be running',
        type: 'van-docker'
      });
    }
  } catch (e) {
    checks.docker = { status: 'error', error: e.message };
  }
  
  return checks;
}

// REAL Docker Security Scanning
async function scanDockerImage(imageName) {
  log(`Starting REAL security scan for: ${imageName}`);
  
  const scanId = Date.now();
  const scanResults = {
    id: scanId,
    image: imageName,
    timestamp: new Date().toISOString(),
    status: 'running'
  };
  
  // Save initial scan state
  const scanFile = path.join(SCAN_DIR, `scan-${scanId}.json`);
  fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2));
  
  try {
    // REAL Trivy Scan
    log('Running REAL Trivy scan...');
    const trivyResult = await safeExec(`trivy image --format json ${imageName}`);
    const trivyFile = path.join(SCAN_DIR, `trivy-${scanId}.json`);
    
    if (trivyResult.success && trivyResult.stdout) {
      fs.writeFileSync(trivyFile, trivyResult.stdout);
      const trivyData = JSON.parse(trivyResult.stdout);
      scanResults.trivy = {
        success: true,
        vulnerabilities: trivyData.Results || [],
        summary: trivyData.Metadata ? trivyData.Metadata.OS : 'Unknown'
      };
      
      // Check for critical vulnerabilities
      let criticalCount = 0;
      (trivyData.Results || []).forEach(result => {
        (result.Vulnerabilities || []).forEach(vuln => {
          if (vuln.Severity === 'CRITICAL') criticalCount++;
        });
      });
      
      if (criticalCount > 0) {
        createAlert({
          severity: 'critical',
          title: 'Critical Vulnerabilities Found',
          description: `${criticalCount} CRITICAL vulnerabilities in ${imageName}`,
          type: 'scan-trivy',
          image: imageName
        });
      }
    } else {
      scanResults.trivy = { success: false, error: trivyResult.stderr };
    }
    
    // REAL Grype Scan
    log('Running REAL Grype scan...');
    const grypeResult = await safeExec(`grype ${imageName} -o json`);
    const grypeFile = path.join(SCAN_DIR, `grype-${scanId}.json`);
    
    if (grypeResult.success && grypeResult.stdout) {
      fs.writeFileSync(grypeFile, grypeResult.stdout);
      const grypeData = JSON.parse(grypeResult.stdout);
      scanResults.grype = {
        success: true,
        matches: grypeData.matches || [],
        source: grypeData.source || {}
      };
    } else {
      scanResults.grype = { success: false, error: grypeResult.stderr };
    }
    
    scanResults.status = 'completed';
    scanResults.completedAt = new Date().toISOString();
    
  } catch (error) {
    scanResults.status = 'error';
    scanResults.error = error.message;
    log(`Scan error: ${error.message}`);
  }
  
  // Save final results
  fs.writeFileSync(scanFile, JSON.stringify(scanResults, null, 2));
  return scanResults;
}

// REAL Auto-fix System
async function autoFixImage(imageName) {
  log(`Starting REAL auto-fix for: ${imageName}`);
  
  const fixId = Date.now();
  const fixResults = {
    id: fixId,
    image: imageName,
    timestamp: new Date().toISOString(),
    status: 'running',
    steps: []
  };
  
  const fixFile = path.join(SCAN_DIR, `fix-${fixId}.json`);
  fs.writeFileSync(fixFile, JSON.stringify(fixResults, null, 2));
  
  try {
    // Step 1: Pull latest image
    fixResults.steps.push({ step: 'pull_image', start: new Date().toISOString() });
    const pullResult = await safeExec(`docker pull ${imageName}`);
    fixResults.steps[0].result = pullResult.success ? 'success' : 'failed';
    fixResults.steps[0].end = new Date().toISOString();
    
    if (!pullResult.success) {
      throw new Error(`Failed to pull image: ${pullResult.stderr}`);
    }
    
    // Step 2: Create temporary container
    fixResults.steps.push({ step: 'create_container', start: new Date().toISOString() });
    const containerName = `temp-fix-${fixId}`;
    const createResult = await safeExec(`docker create --name ${containerName} ${imageName} sleep 3600`);
    fixResults.steps[1].result = createResult.success ? 'success' : 'failed';
    fixResults.steps[1].end = new Date().toISOString();
    
    if (!createResult.success) {
      throw new Error(`Failed to create container: ${createResult.stderr}`);
    }
    
    // Step 3: Update packages in container
    fixResults.steps.push({ step: 'update_packages', start: new Date().toISOString() });
    const updateResult = await safeExec(`docker start ${containerName} && docker exec ${containerName} apt-get update && docker exec ${containerName} apt-get upgrade -y`);
    fixResults.steps[2].result = updateResult.success ? 'success' : 'partial';
    fixResults.steps[2].end = new Date().toISOString();
    
    // Step 4: Commit hardened image
    fixResults.steps.push({ step: 'commit_image', start: new Date().toISOString() });
    const newImageName = `${imageName.split(':')[0]}-hardened-${fixId}:latest`;
    const commitResult = await safeExec(`docker commit ${containerName} ${newImageName}`);
    fixResults.steps[3].result = commitResult.success ? 'success' : 'failed';
    fixResults.steps[3].end = new Date().toISOString();
    fixResults.newImage = newImageName;
    
    if (!commitResult.success) {
      throw new Error(`Failed to commit image: ${commitResult.stderr}`);
    }
    
    // Step 5: Cleanup
    fixResults.steps.push({ step: 'cleanup', start: new Date().toISOString() });
    await safeExec(`docker stop ${containerName} && docker rm ${containerName}`);
    fixResults.steps[4].result = 'success';
    fixResults.steps[4].end = new Date().toISOString();
    
    fixResults.status = 'completed';
    createAlert({
      severity: 'low',
      title: 'Image Auto-Fix Completed',
      description: `Hardened image created: ${newImageName}`,
      type: 'auto-fix',
      image: newImageName
    });
    
  } catch (error) {
    fixResults.status = 'error';
    fixResults.error = error.message;
    createAlert({
      severity: 'high',
      title: 'Auto-Fix Failed',
      description: error.message,
      type: 'auto-fix-error',
      image: imageName
    });
  }
  
  fs.writeFileSync(fixFile, JSON.stringify(fixResults, null, 2));
  return fixResults;
}

// API Routes

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// System Health (VAN)
app.get('/api/van', async (req, res) => {
  try {
    const health = await checkSystemHealth();
    res.json({ success: true, data: health });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Docker Scan
app.post('/api/scan', async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) {
      return res.status(400).json({ success: false, error: 'Image name required' });
    }
    
    const scanResults = await scanDockerImage(image);
    res.json({ success: true, data: scanResults });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get Scan Results
app.get('/api/scans', (req, res) => {
  try {
    const scanFiles = fs.readdirSync(SCAN_DIR)
      .filter(file => file.startsWith('scan-') && file.endsWith('.json'))
      .map(file => {
        try {
          return JSON.parse(fs.readFileSync(path.join(SCAN_DIR, file), 'utf8'));
        } catch (e) {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.json({ success: true, data: scanFiles });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Auto-fix
app.post('/api/auto-fix', async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) {
      return res.status(400).json({ success: false, error: 'Image name required' });
    }
    
    const fixResults = await autoFixImage(image);
    res.json({ success: true, data: fixResults });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Alerts
app.get('/api/alerts', (req, res) => {
  try {
    const alerts = readAlerts();
    res.json({ success: true, data: alerts });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Mitigate Alert
app.post('/api/alerts/:id/mitigate', (req, res) => {
  try {
    const { id } = req.params;
    const alerts = readAlerts();
    const alertIndex = alerts.findIndex(a => a.id === id);
    
    if (alertIndex === -1) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }
    
    alerts[alertIndex].status = 'mitigated';
    alerts[alertIndex].mitigatedAt = new Date().toISOString();
    writeAlerts(alerts);
    
    res.json({ success: true, data: alerts[alertIndex] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Chat Assistant
app.post('/api/chat', async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.json({ success: true, response: "Please enter a message." });
    }
    
    const lowerMessage = message.toLowerCase();
    
    // Simple rule-based responses
    if (lowerMessage.includes('scan') || lowerMessage.includes('security')) {
      return res.json({ 
        success: true, 
        response: "I can help you scan Docker images for security vulnerabilities. Use the Docker Scan tab to scan an image with Trivy and Grype." 
      });
    }
    
    if (lowerMessage.includes('van') || lowerMessage.includes('monitor')) {
      return res.json({ 
        success: true, 
        response: "VAN monitoring checks system health including CPU, memory, disk, network, firewall, and Docker status. Check the VAN tab for real-time monitoring." 
      });
    }
    
    if (lowerMessage.includes('alert') || lowerMessage.includes('issue')) {
      return res.json({ 
        success: true, 
        response: "Alerts show security issues found during scans or system monitoring. You can mitigate alerts from the Alerts tab." 
      });
    }
    
    if (lowerMessage.includes('fix') || lowerMessage.includes('auto-fix')) {
      return res.json({ 
        success: true, 
        response: "Auto-fix can harden Docker images by updating packages and creating secured versions. Use the Auto-Fix tab to secure your images." 
      });
    }
    
    if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
      return res.json({ 
        success: true, 
        response: "Hello! I'm your DevSecOps assistant. I can help you with security scanning, system monitoring, and auto-fixing vulnerabilities." 
      });
    }
    
    return res.json({ 
      success: true, 
      response: "I understand you're asking about: '" + message + "'. I can help with Docker security scanning, system monitoring (VAN), alerts management, and auto-fixing images. Which would you like to know more about?" 
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'DevSecOps Dashboard is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Start server
app.listen(PORT, () => {
  log(`🚀 REAL DevSecOps Dashboard started on port ${PORT}`);
  log(`📊 Dashboard: http://localhost:${PORT}`);
  log(`🔧 API Health: http://localhost:${PORT}/api/health`);
  log(`🐳 Make sure Docker, Trivy, and Grype are installed for full functionality`);
});
