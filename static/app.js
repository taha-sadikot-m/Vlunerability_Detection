// app.js - VulnDetect AI Frontend
class VulnDetectApp {
  constructor() {
    this.vulnerabilities = [
      {
        id: "VULN-001",
        type: "SQL Injection",
        severity: "Critical",
        cvss_score: 9.8,
        cve: "CVE-2023-1234",
        cwe: "CWE-89",
        file: "src/database/user_service.py",
        line: 45,
        confidence: 95,
        description: "SQL injection vulnerability in user authentication function",
        code_snippet: "query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\"",
        mitigation: "Use parameterized queries or prepared statements",
        fix_suggestion: "query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\ncursor.execute(query, (username, password))"
      },
      {
        id: "VULN-002", 
        type: "Cross-Site Scripting (XSS)",
        severity: "High",
        cvss_score: 7.4,
        cve: "CVE-2023-5678",
        cwe: "CWE-79",
        file: "src/web/templates/profile.html",
        line: 23,
        confidence: 87,
        description: "Reflected XSS vulnerability in user profile display",
        code_snippet: "<div>Welcome {{ user.name }}</div>",
        mitigation: "Properly escape user input before rendering",
        fix_suggestion: "<div>Welcome {{ user.name|e }}</div>"
      },
      {
        id: "VULN-003",
        type: "Remote Code Execution",
        severity: "Critical", 
        cvss_score: 9.9,
        cve: "CVE-2023-9999",
        cwe: "CWE-94",
        file: "src/api/file_processor.py",
        line: 78,
        confidence: 92,
        description: "Code injection via eval() function with user input",
        code_snippet: "result = eval(user_expression)",
        mitigation: "Never use eval() with user input. Use safe alternatives like ast.literal_eval()",
        fix_suggestion: "import ast\ntry:\n    result = ast.literal_eval(user_expression)\nexcept ValueError:\n    result = None"
      },
      {
        id: "VULN-004",
        type: "Insecure Direct Object Reference",
        severity: "Medium",
        cvss_score: 6.5,
        cve: "CVE-2023-4321",
        cwe: "CWE-639",
        file: "src/api/document_controller.py", 
        line: 34,
        confidence: 78,
        description: "Missing authorization check allows access to any document",
        code_snippet: "document = Document.get(document_id)",
        mitigation: "Implement proper authorization checks",
        fix_suggestion: "if not user.can_access_document(document_id):\n    return forbidden()\ndocument = Document.get(document_id)"
      },
      {
        id: "VULN-005",
        type: "Server-Side Request Forgery",
        severity: "High",
        cvss_score: 8.1,
        cve: "CVE-2023-7777",
        cwe: "CWE-918",
        file: "src/utils/http_client.py",
        line: 56,
        confidence: 83,
        description: "SSRF vulnerability in URL fetching function",
        code_snippet: "response = requests.get(user_provided_url)",
        mitigation: "Validate and whitelist allowed URLs and domains",
        fix_suggestion: "allowed_domains = ['api.example.com', 'cdn.example.com']\nif not is_allowed_url(user_provided_url, allowed_domains):\n    return error('Invalid URL')\nresponse = requests.get(user_provided_url)"
      }
    ];
    
    this.scanStats = {
      total_files: 45,
      lines_scanned: 15420,
      total_vulnerabilities: 5,
      critical: 2,
      high: 2, 
      medium: 1,
      low: 0,
      security_score: 3.2,
      scan_duration: "2m 34s"
    };

    this.uploadedFiles = [];
    this.isScanning = false;
    this.charts = {};
    
    // Initialize Socket.IO connection
    this.socket = io();
    this.setupSocketEvents();
    
    this.init();
  }

  setupSocketEvents() {
    // Handle socket connection
    this.socket.on('connect', () => {
      console.log('Connected to VulnDetect AI Backend');
    });

    // Handle scan progress updates
    this.socket.on('scan_progress', (data) => {
      console.log('Scan progress:', data);
      const progressBar = document.getElementById('progressBar');
      const logOutput = document.getElementById('logOutput');
      
      if (progressBar && logOutput) {
        progressBar.style.width = data.progress + '%';
        logOutput.textContent += data.message + '\n';
        logOutput.scrollTop = logOutput.scrollHeight;
      }
    });

    // Handle scan completion
    this.socket.on('scan_completed', (data) => {
      console.log('Scan completed:', data);
      this.isScanning = false;
      this.updateScanButton();
      
      // Update with real data from backend
      if (data.results) {
        this.vulnerabilities = data.results.vulnerabilities || this.vulnerabilities;
        this.showResults();
      }
    });

    // Handle scan errors
    this.socket.on('scan_error', (data) => {
      console.error('Scan error:', data);
      this.isScanning = false;
      this.updateScanButton();
      
      const progressStatus = document.getElementById('progressStatus');
      const logOutput = document.getElementById('logOutput');
      
      if (progressStatus && logOutput) {
        progressStatus.textContent = 'Failed';
        progressStatus.className = 'status status--error';
        logOutput.textContent += '[ERROR] ' + data.error + '\n';
        logOutput.scrollTop = logOutput.scrollHeight;
      }
    });
  }

  init() {
    this.setupNavigation();
    this.setupFileUpload();
    this.setupScanConfig();
    this.setupSearch();
    this.setupExports();
  }

  setupNavigation() {
    const navLinks = document.querySelectorAll('.nav__link');
    const sections = document.querySelectorAll('.section');

    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetSection = link.dataset.section;
        
        // Update active nav
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        // Show target section
        sections.forEach(s => s.classList.add('hidden'));
        const targetElement = document.getElementById(targetSection);
        if (targetElement) {
          targetElement.classList.remove('hidden');
        }
      });
    });
  }

  setupFileUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const browseLabel = document.getElementById('browseLabel');
    const clearBtn = document.getElementById('clearFilesBtn');
    const preview = document.getElementById('filePreview');

    // Browse label click - trigger file input
    browseLabel.addEventListener('click', (e) => {
      e.preventDefault();
      fileInput.click();
    });
    
    // Clear files
    clearBtn.addEventListener('click', () => {
      this.uploadedFiles = [];
      fileInput.value = '';
      preview.innerHTML = '';
      preview.classList.add('hidden');
      clearBtn.classList.add('hidden');
      this.updateScanButton();
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
      this.handleFiles(Array.from(e.target.files));
    });

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      this.handleFiles(Array.from(e.dataTransfer.files));
    });

    // Click on drop zone to browse
    dropZone.addEventListener('click', (e) => {
      if (e.target === dropZone || e.target.tagName === 'SVG' || e.target.tagName === 'PATH') {
        fileInput.click();
      }
    });
  }

  handleFiles(files) {
    const allowedExtensions = ['.py', '.js', '.java', '.php', '.go', '.c', '.cpp', '.zip', '.tar'];
    const validFiles = files.filter(file => {
      const ext = '.' + file.name.split('.').pop().toLowerCase();
      return allowedExtensions.includes(ext);
    });

    if (validFiles.length > 0) {
      // Store file objects for upload
      this.uploadedFiles = [...this.uploadedFiles, ...validFiles];
      this.updateFilePreview();
      this.updateScanButton();
    } else {
      alert('Please upload valid source code files (.py, .js, .java, .php, .go, .c, .cpp, .zip, .tar)');
    }
  }

  updateFilePreview() {
    const preview = document.getElementById('filePreview');
    const clearBtn = document.getElementById('clearFilesBtn');
    
    if (this.uploadedFiles.length === 0) return;

    preview.innerHTML = this.uploadedFiles.map(file => 
      `<li><strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)</li>`
    ).join('');
    
    preview.classList.remove('hidden');
    clearBtn.classList.remove('hidden');
  }

  updateScanButton() {
    const startBtn = document.getElementById('startScanBtn');
    const hasFiles = this.uploadedFiles.length > 0;
    
    startBtn.disabled = !hasFiles || this.isScanning;
    
    if (!hasFiles) {
      startBtn.title = 'Upload at least one source file to enable scanning';
      startBtn.style.backgroundColor = 'var(--color-gray-400)';
      startBtn.style.color = 'var(--color-gray-200)';
      startBtn.style.opacity = '0.6';
      startBtn.style.cursor = 'not-allowed';
    } else if (this.isScanning) {
      startBtn.title = 'Scan in progress...';
      startBtn.style.backgroundColor = 'var(--color-gray-400)';
      startBtn.style.color = 'var(--color-gray-200)';
      startBtn.style.opacity = '0.6';
      startBtn.style.cursor = 'not-allowed';
    } else {
      startBtn.title = 'Start vulnerability scan';
      startBtn.style.backgroundColor = 'var(--color-primary)';
      startBtn.style.color = 'var(--color-btn-primary-text)';
      startBtn.style.opacity = '1';
      startBtn.style.cursor = 'pointer';
    }
  }

  setupScanConfig() {
    const form = document.getElementById('scanConfigForm');
    
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (this.uploadedFiles.length === 0) {
        alert('Please upload at least one source code file before starting the scan.');
        return;
      }
      if (!this.isScanning) {
        this.startScan();
      }
    });
  }

  async startScan() {
    this.isScanning = true;
    this.updateScanButton();
    
    const progressSection = document.getElementById('progressSection');
    const progressBar = document.getElementById('progressBar');
    const progressStatus = document.getElementById('progressStatus');
    const logOutput = document.getElementById('logOutput');
    
    // Clear previous results
    logOutput.textContent = '';
    progressBar.style.width = '0%';
    
    progressSection.classList.remove('hidden');
    progressStatus.textContent = 'Scanning';
    progressStatus.className = 'status status--warning';
    
    // Prepare scan configuration
    const scanConfig = {
      files: this.uploadedFiles.map(file => ({
        name: file.name,
        size: file.size,
        type: file.type
      })),
      language: document.getElementById('languageSelect').value,
      sast_enabled: document.querySelector('input[value="SAST Analysis"]').checked,
      llm_analysis: document.querySelector('input[value="LLM Deep Analysis"]').checked,
      dependency_scan: document.querySelector('input[value="Dependency Scanning"]').checked,
      cve_lookup: document.querySelector('input[value="CVE/CWE Lookup"]').checked,
      deep_analysis: document.querySelector('input[name="depth"][value="Deep"]').checked
    };
    
    try {
      // Log initial message
      logOutput.textContent += '[INFO] Preparing scan configuration...\n';
      
      // Make API call to start scan
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanConfig)
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to start scan');
      }
      
      // Log success message
      logOutput.textContent += `[INFO] Scan initiated with ID: ${data.scan_id}\n`;
      
      // Subscribe to scan updates via Socket.IO
      this.socket.emit('subscribe_scan', { scan_id: data.scan_id });
      
      // For demo/fallback purposes, if socket doesn't work
      if (!this.socket.connected) {
        await this.simulateScanProgress();
        this.showResults();
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      logOutput.textContent += `[ERROR] ${error.message}\n`;
      progressStatus.textContent = 'Failed';
      progressStatus.className = 'status status--error';
      this.isScanning = false;
      this.updateScanButton();
    }
  }
  
  // Keep the simulation for demo/fallback purposes
  async simulateScanProgress() {
    const progressBar = document.getElementById('progressBar');
    const logOutput = document.getElementById('logOutput');
    
    const steps = [
      { progress: 10, message: '[INFO] Initializing scan engine...' },
      { progress: 20, message: '[INFO] Loading vulnerability signatures...' },
      { progress: 30, message: '[INFO] Parsing source code files...' },
      { progress: 50, message: '[INFO] Running SAST analysis...' },
      { progress: 70, message: '[INFO] Performing LLM-based deep analysis...' },
      { progress: 85, message: '[INFO] Cross-referencing CVE database...' },
      { progress: 95, message: '[INFO] Generating mitigation recommendations...' },
      { progress: 100, message: '[SUCCESS] Scan completed successfully!' }
    ];

    for (const step of steps) {
      await this.delay(800);
      progressBar.style.width = step.progress + '%';
      logOutput.textContent += step.message + '\n';
      logOutput.scrollTop = logOutput.scrollHeight;
    }

    const progressStatus = document.getElementById('progressStatus');
    progressStatus.textContent = 'Complete';
    progressStatus.className = 'status status--success';
    
    this.isScanning = false;
    this.updateScanButton();
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  showResults() {
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.classList.remove('hidden');
    
    this.updateOverviewCards();
    this.createCharts();
    this.populateFindingsTable();
  }

  updateOverviewCards() {
    document.getElementById('totalVulns').textContent = this.scanStats.total_vulnerabilities;
    document.getElementById('criticalCount').textContent = this.scanStats.critical;
    document.getElementById('highCount').textContent = this.scanStats.high;
    document.getElementById('mediumCount').textContent = this.scanStats.medium;
    document.getElementById('lowCount').textContent = this.scanStats.low;
    document.getElementById('securityScore').textContent = this.scanStats.security_score + '/10';
  }

  createCharts() {
    // Destroy existing charts to prevent canvas reuse issues
    if (this.charts.pie) {
      this.charts.pie.destroy();
    }
    if (this.charts.bar) {
      this.charts.bar.destroy();
    }

    // Vulnerability Distribution Pie Chart
    const pieCtx = document.getElementById('vulnPie').getContext('2d');
    this.charts.pie = new Chart(pieCtx, {
      type: 'pie',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [this.scanStats.critical, this.scanStats.high, this.scanStats.medium, this.scanStats.low],
          backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#f5f5f5' }
          }
        }
      }
    });

    // Top Vulnerable Files Bar Chart
    const barCtx = document.getElementById('fileBar').getContext('2d');
    this.charts.bar = new Chart(barCtx, {
      type: 'bar',
      data: {
        labels: ['user_service.py', 'profile.html', 'file_processor.py', 'document_controller.py', 'http_client.py'],
        datasets: [{
          label: 'Vulnerabilities',
          data: [1, 1, 1, 1, 1],
          backgroundColor: ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#f5f5f5' }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: { color: '#f5f5f5' }
          },
          x: {
            ticks: { color: '#f5f5f5' }
          }
        }
      }
    });
  }

  populateFindingsTable() {
    const tbody = document.querySelector('#findingsTable tbody');
    tbody.innerHTML = this.vulnerabilities.map(vuln => `
      <tr onclick="app.showFindingDetail('${vuln.id}')" style="cursor: pointer;">
        <td>${vuln.id}</td>
        <td>${vuln.type}</td>
        <td><span class="badge ${vuln.severity}">${vuln.severity}</span></td>
        <td>${vuln.file}</td>
        <td>${vuln.line}</td>
        <td>${vuln.cve}</td>
        <td>${vuln.confidence}%</td>
      </tr>
    `).join('');
  }

  showFindingDetail(vulnId) {
    const vuln = this.vulnerabilities.find(v => v.id === vulnId);
    if (!vuln) return;

    const detailDiv = document.getElementById('findingDetail');
    detailDiv.innerHTML = `
      <div class="card__header">
        <h2>${vuln.type} - ${vuln.id}</h2>
        <span class="badge ${vuln.severity}">${vuln.severity}</span>
      </div>
      <div class="card__body">
        <div class="grid-2-col gap-16">
          <div>
            <h3>Vulnerability Details</h3>
            <p><strong>File:</strong> ${vuln.file}</p>
            <p><strong>Line:</strong> ${vuln.line}</p>
            <p><strong>CVE:</strong> ${vuln.cve}</p>
            <p><strong>CWE:</strong> ${vuln.cwe}</p>
            <p><strong>CVSS Score:</strong> ${vuln.cvss_score}</p>
            <p><strong>Confidence:</strong> ${vuln.confidence}%</p>
            <p><strong>Description:</strong> ${vuln.description}</p>
          </div>
          <div>
            <h3>Code Snippet</h3>
            <pre><code>${vuln.code_snippet}</code></pre>
            <h3>Mitigation</h3>
            <p>${vuln.mitigation}</p>
            <h3>Suggested Fix</h3>
            <pre><code>${vuln.fix_suggestion}</code></pre>
            <button class="btn btn--primary mt-8" onclick="app.applyFix('${vuln.id}')">Apply Fix</button>
          </div>
        </div>
      </div>
    `;
    detailDiv.classList.remove('hidden');
  }

  applyFix(vulnId) {
    alert(`Fix would be applied for ${vulnId}. This is a demo - no actual changes made.`);
  }

  setupSearch() {
    const searchInput = document.getElementById('findingsSearch');
    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      const rows = document.querySelectorAll('#findingsTable tbody tr');
      
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
      });
    });
  }

  setupExports() {
    document.getElementById('exportJSON').addEventListener('click', () => {
      this.exportData('json');
    });
    
    document.getElementById('exportCSV').addEventListener('click', () => {
      this.exportData('csv');
    });
    
    document.getElementById('exportPDF').addEventListener('click', () => {
      this.exportData('pdf');
    });
  }

  exportData(format) {
    const data = {
      scan_stats: this.scanStats,
      vulnerabilities: this.vulnerabilities,
      timestamp: new Date().toISOString()
    };

    switch (format) {
      case 'json':
        this.downloadFile('vulnerabilities.json', JSON.stringify(data, null, 2), 'application/json');
        break;
      case 'csv':
        const csv = this.convertToCSV(this.vulnerabilities);
        this.downloadFile('vulnerabilities.csv', csv, 'text/csv');
        break;
      case 'pdf':
        alert('PDF export would generate a comprehensive report. This is a demo.');
        break;
    }
  }

  convertToCSV(data) {
    const headers = ['ID', 'Type', 'Severity', 'File', 'Line', 'CVE', 'CWE', 'Confidence', 'Description'];
    const rows = data.map(item => [
      item.id, item.type, item.severity, item.file, item.line, 
      item.cve, item.cwe, item.confidence, item.description
    ]);
    
    return [headers, ...rows].map(row => 
      row.map(field => `"${field}"`).join(',')
    ).join('\n');
  }

  downloadFile(filename, content, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

// Initialize the application
const app = new VulnDetectApp();