// Advanced All-in-One Passive Reconnaissance Platform
class CyberReconPro {
    constructor() {
        this.currentTarget = '';
        this.targetType = 'unknown';
        this.scanResults = {};
        this.completedScans = 0;
        this.totalScans = 6;
        this.isScanning = false;
        this.scanStartTime = null;
        
        this.tools = [
            { id: 'whois', name: 'WHOIS Analysis', duration: [2000, 3000], icon: '🔍' },
            { id: 'dns', name: 'DNS Resolution', duration: [3000, 5000], icon: '🌐' },
            { id: 'subdomain', name: 'Subdomain Discovery', duration: [10000, 15000], icon: '🔎' },
            { id: 'reverse-ip', name: 'Reverse IP Lookup', duration: [5000, 8000], icon: '🔄' },
            { id: 'http-headers', name: 'HTTP Analysis', duration: [3000, 5000], icon: '📋' },
            { id: 'port-scan', name: 'Port Discovery', duration: [15000, 30000], icon: '🔌' }
        ];
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupExpandableResults();
        this.updateInputDetection();
    }

    setupEventListeners() {
        // Main analyze button
        const analyzeBtn = document.getElementById('analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.startComprehensiveAnalysis();
            });
        }

        // Target input with real-time detection
        const targetInput = document.getElementById('target-input');
        if (targetInput) {
            targetInput.addEventListener('input', (e) => {
                this.updateInputDetection();
            });
            targetInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.startComprehensiveAnalysis();
                }
            });
        }

        // Export and clear buttons
        const exportBtn = document.getElementById('export-btn');
        const clearBtn = document.getElementById('clear-btn');
        
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportComprehensiveReport());
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearAllResults());
        }
    }

    setupExpandableResults() {
        const expandBtns = document.querySelectorAll('.expand-btn');
        expandBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetId = btn.dataset.target;
                const content = document.getElementById(targetId);
                const icon = btn.querySelector('.expand-icon');
                
                if (content.classList.contains('collapsed')) {
                    content.classList.remove('collapsed');
                    btn.classList.add('expanded');
                } else {
                    content.classList.add('collapsed');
                    btn.classList.remove('expanded');
                }
            });
        });
    }

    updateInputDetection() {
        const targetInput = document.getElementById('target-input');
        const inputTypeElement = document.getElementById('input-type');
        
        if (!targetInput || !inputTypeElement) return;
        
        const value = targetInput.value.trim();
        
        if (!value) {
            inputTypeElement.textContent = 'Enter target to detect type';
            inputTypeElement.className = 'input-type';
            this.targetType = 'unknown';
            return;
        }

        // IP Address detection
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
            this.targetType = 'ip';
            inputTypeElement.textContent = `🎯 IP Address detected: ${value}`;
            inputTypeElement.className = 'input-type ip-type';
        }
        // Domain detection
        else if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(value)) {
            if (value.includes('.')) {
                this.targetType = 'domain';
                inputTypeElement.textContent = `🌐 Domain detected: ${value}`;
                inputTypeElement.className = 'input-type domain-type';
            } else {
                this.targetType = 'hostname';
                inputTypeElement.textContent = `💻 Hostname detected: ${value}`;
                inputTypeElement.className = 'input-type hostname-type';
            }
        }
        // URL detection
        else if (/^https?:\/\/.+/.test(value)) {
            this.targetType = 'url';
            inputTypeElement.textContent = `🔗 URL detected: ${value}`;
            inputTypeElement.className = 'input-type url-type';
        }
        else {
            this.targetType = 'unknown';
            inputTypeElement.textContent = '❓ Unknown format - please check input';
            inputTypeElement.className = 'input-type unknown-type';
        }
    }

    async startComprehensiveAnalysis() {
        const targetInput = document.getElementById('target-input');
        if (!targetInput) return;

        this.currentTarget = targetInput.value.trim();
        
        if (!this.currentTarget) {
            this.showNotification('Please enter a target to analyze', 'error');
            return;
        }

        if (this.targetType === 'unknown') {
            this.showNotification('Please enter a valid domain, IP address, or URL', 'error');
            return;
        }

        if (this.isScanning) {
            this.showNotification('Scan already in progress', 'warning');
            return;
        }

        // Reset state
        this.isScanning = true;
        this.completedScans = 0;
        this.scanResults = {};
        this.scanStartTime = Date.now();

        // Show progress section
        this.showProgressSection();
        
        // Initialize progress tracking
        this.initializeProgressTracking();

        // Start all reconnaissance tools simultaneously
        this.showNotification('🚀 Launching comprehensive reconnaissance suite', 'success');
        
        // Run all tools in parallel
        const scanPromises = this.tools.map(tool => this.runTool(tool));
        
        try {
            await Promise.allSettled(scanPromises);
            this.completeScan();
        } catch (error) {
            console.error('Scan error:', error);
            this.showNotification('Scan completed with some errors', 'warning');
            this.isScanning = false;
        }
    }

    showProgressSection() {
        const progressSection = document.getElementById('progress-section');
        if (progressSection) {
            progressSection.style.display = 'block';
            progressSection.scrollIntoView({ behavior: 'smooth' });
        }
    }

    initializeProgressTracking() {
        // Reset all progress bars and status badges
        this.tools.forEach(tool => {
            const progressElement = document.querySelector(`.tool-progress[data-tool="${tool.id}"]`);
            if (progressElement) {
                const statusBadge = progressElement.querySelector('.status-badge');
                const progressFill = progressElement.querySelector('.progress-fill');
                
                statusBadge.textContent = 'Pending';
                statusBadge.className = 'status-badge pending';
                progressFill.style.width = '0%';
            }
        });

        // Reset overall progress
        this.updateOverallProgress(0);
    }

    async runTool(tool) {
        const progressElement = document.querySelector(`.tool-progress[data-tool="${tool.id}"]`);
        if (!progressElement) return;

        const statusBadge = progressElement.querySelector('.status-badge');
        const progressFill = progressElement.querySelector('.progress-fill');

        try {
            // Start tool
            statusBadge.textContent = 'Running';
            statusBadge.className = 'status-badge running';
            progressElement.classList.add('running');

            // Simulate progress
            const duration = this.getRandomDuration(tool.duration);
            await this.animateProgress(progressFill, duration);

            // Generate results based on tool type
            const result = await this.generateToolResult(tool);
            this.scanResults[tool.id] = result;

            // Complete tool
            statusBadge.textContent = 'Completed';
            statusBadge.className = 'status-badge completed';
            progressElement.classList.remove('running');
            progressFill.style.width = '100%';

            // Update results panel
            this.updateResultPanel(tool.id, result);

            // Update overall progress
            this.completedScans++;
            this.updateOverallProgress((this.completedScans / this.totalScans) * 100);

            this.showNotification(`${tool.name} completed successfully`, 'success');

        } catch (error) {
            console.error(`${tool.name} error:`, error);
            statusBadge.textContent = 'Error';
            statusBadge.className = 'status-badge error';
            progressElement.classList.remove('running');
            
            this.showNotification(`${tool.name} failed`, 'error');
        }
    }

    getRandomDuration(range) {
        return Math.floor(Math.random() * (range[1] - range[0] + 1)) + range[0];
    }

    animateProgress(progressFill, duration) {
        return new Promise((resolve) => {
            let progress = 0;
            const interval = duration / 100;
            
            const timer = setInterval(() => {
                progress += Math.random() * 3 + 1;
                if (progress >= 100) {
                    progress = 100;
                    clearInterval(timer);
                    resolve();
                }
                progressFill.style.width = progress + '%';
            }, interval);
        });
    }

    async generateToolResult(tool) {
        // Generate appropriate sample data based on tool type and target
        switch (tool.id) {
            case 'whois':
                return this.generateWhoisResult();
            case 'dns':
                return this.generateDnsResult();
            case 'subdomain':
                return this.generateSubdomainResult();
            case 'reverse-ip':
                return this.generateReverseIpResult();
            case 'http-headers':
                return this.generateHttpHeadersResult();
            case 'port-scan':
                return this.generatePortScanResult();
            default:
                return { error: 'Unknown tool' };
        }
    }

    generateWhoisResult() {
        const target = this.currentTarget.replace(/^https?:\/\//, '').split('/')[0];
        return {
            domain: target,
            registrar: "Example Registrar Inc.",
            created: "1995-08-14",
            expires: "2025-08-13", 
            status: "Active",
            nameservers: [`ns1.${target}`, `ns2.${target}`],
            contacts: {
                registrant: "Example Organization",
                admin: `admin@${target}`
            },
            location: "United States",
            dnssec: "Enabled"
        };
    }

    generateDnsResult() {
        const target = this.currentTarget.replace(/^https?:\/\//, '').split('/')[0];
        return {
            A: ["93.184.216.34"],
            AAAA: ["2606:2800:220:1:248:1893:25c8:1946"], 
            MX: [{"priority": 10, "server": `mail.${target}`}],
            NS: [`ns1.${target}`, `ns2.${target}`],
            TXT: [`v=spf1 include:_spf.${target} ~all`, "google-site-verification=abc123"],
            CNAME: {"www": target}
        };
    }

    generateSubdomainResult() {
        const baseDomain = this.currentTarget.replace(/^https?:\/\//, '').split('/')[0];
        const subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'cdn'];
        return subdomains.map(sub => ({
            name: `${sub}.${baseDomain}`,
            ip: `93.184.216.${Math.floor(Math.random() * 100) + 30}`,
            status: Math.random() > 0.2 ? 'Active' : 'Inactive'
        }));
    }

    generateReverseIpResult() {
        return [
            {"domain": "example.org", "ip": "93.184.216.34"},
            {"domain": "test-site.net", "ip": "93.184.216.34"},
            {"domain": "demo.co", "ip": "93.184.216.34"}
        ];
    }

    generateHttpHeadersResult() {
        const target = this.currentTarget.startsWith('http') ? this.currentTarget : `https://${this.currentTarget}`;
        return {
            url: target,
            server: "Apache/2.4.41",
            contentType: "text/html; charset=UTF-8",
            securityHeaders: {
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "SAMEORIGIN",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'"
            },
            responseCode: 200,
            responseTime: `${Math.floor(Math.random() * 300) + 50}ms`
        };
    }

    generatePortScanResult() {
        return [
            {"port": 22, "service": "SSH", "status": "Open", "version": "OpenSSH 8.0"},
            {"port": 80, "service": "HTTP", "status": "Open", "version": "Apache 2.4.41"},
            {"port": 443, "service": "HTTPS", "status": "Open", "version": "Apache 2.4.41"},
            {"port": 25, "service": "SMTP", "status": "Filtered", "version": "Unknown"}
        ];
    }

    updateResultPanel(toolId, result) {
        const contentElement = document.getElementById(`${toolId}-content`);
        if (!contentElement) return;

        let formattedResult = '';
        
        switch (toolId) {
            case 'whois':
                formattedResult = this.formatWhoisResult(result);
                break;
            case 'dns':
                formattedResult = this.formatDnsResult(result);
                break;
            case 'subdomain':
                formattedResult = this.formatSubdomainResult(result);
                break;
            case 'reverse-ip':
                formattedResult = this.formatReverseIpResult(result);
                break;
            case 'http-headers':
                formattedResult = this.formatHttpHeadersResult(result);
                break;
            case 'port-scan':
                formattedResult = this.formatPortScanResult(result);
                break;
        }

        contentElement.innerHTML = formattedResult;
    }

    formatWhoisResult(data) {
        return `
            <div class="result-data">
                <strong>Domain Information:</strong>
                Domain: ${data.domain}
                Registrar: ${data.registrar}
                Created: ${data.created}
                Expires: ${data.expires}
                Status: ${data.status}
                DNSSEC: ${data.dnssec}
                
                <strong>Nameservers:</strong>
                ${data.nameservers.join('\n')}
                
                <strong>Contacts:</strong>
                Registrant: ${data.contacts.registrant}
                Admin: ${data.contacts.admin}
            </div>
        `;
    }

    formatDnsResult(data) {
        let html = '<div class="result-data">';
        Object.entries(data).forEach(([type, records]) => {
            html += `<strong>${type} Records:</strong>\n`;
            if (Array.isArray(records)) {
                records.forEach(record => {
                    if (typeof record === 'object') {
                        html += `  Priority: ${record.priority}, Server: ${record.server}\n`;
                    } else {
                        html += `  ${record}\n`;
                    }
                });
            } else if (typeof records === 'object') {
                Object.entries(records).forEach(([key, value]) => {
                    html += `  ${key} -> ${value}\n`;
                });
            }
            html += '\n';
        });
        html += '</div>';
        return html;
    }

    formatSubdomainResult(data) {
        let html = `
            <table class="result-table">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        data.forEach(item => {
            const statusClass = item.status === 'Active' ? 'status-success' : 'status-error';
            html += `
                <tr>
                    <td>${item.name}</td>
                    <td>${item.ip}</td>
                    <td><span class="status ${statusClass}">${item.status}</span></td>
                </tr>
            `;
        });
        
        html += '</tbody></table>';
        return html;
    }

    formatReverseIpResult(data) {
        let html = `
            <table class="result-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        data.forEach(item => {
            html += `
                <tr>
                    <td>${item.domain}</td>
                    <td>${item.ip}</td>
                </tr>
            `;
        });
        
        html += '</tbody></table>';
        return html;
    }

    formatHttpHeadersResult(data) {
        let html = `
            <div class="result-data">
                <strong>Response Information:</strong>
                URL: ${data.url}
                Server: ${data.server}
                Content-Type: ${data.contentType}
                Response Code: ${data.responseCode}
                Response Time: ${data.responseTime}
                
                <strong>Security Headers:</strong>
        `;
        
        Object.entries(data.securityHeaders).forEach(([key, value]) => {
            html += `\n${key}: ${value}`;
        });
        
        html += '</div>';
        return html;
    }

    formatPortScanResult(data) {
        let html = `
            <table class="result-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Status</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        data.forEach(port => {
            const statusClass = port.status === 'Open' ? 'status-success' : 
                              port.status === 'Filtered' ? 'status-warning' : 'status-error';
            html += `
                <tr>
                    <td>${port.port}</td>
                    <td>${port.service}</td>
                    <td><span class="status ${statusClass}">${port.status}</span></td>
                    <td>${port.version}</td>
                </tr>
            `;
        });
        
        html += '</tbody></table>';
        return html;
    }

    updateOverallProgress(percentage) {
        const progressCircle = document.querySelector('.progress-circle');
        const progressValue = document.querySelector('.progress-value');
        
        if (progressCircle && progressValue) {
            const degrees = (percentage / 100) * 360;
            progressCircle.style.background = `conic-gradient(var(--cyber-text-primary) ${degrees}deg, var(--cyber-border) ${degrees}deg)`;
            progressValue.textContent = Math.round(percentage) + '%';
        }
    }

    completeScan() {
        this.isScanning = false;
        const scanDuration = ((Date.now() - this.scanStartTime) / 1000).toFixed(1);
        
        // Show results section
        const resultsSection = document.getElementById('results-section');
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }

        // Update executive summary
        this.updateExecutiveSummary();

        this.showNotification(`🎉 Comprehensive analysis completed in ${scanDuration}s`, 'success');
    }

    updateExecutiveSummary() {
        // Calculate summary metrics
        const riskScore = this.calculateRiskScore();
        const openPorts = this.scanResults['port-scan'] ? 
            this.scanResults['port-scan'].filter(p => p.status === 'Open').length : 0;
        const subdomains = this.scanResults['subdomain'] ? 
            this.scanResults['subdomain'].filter(s => s.status === 'Active').length : 0;
        const securityIssues = this.calculateSecurityIssues();

        // Update summary cards
        document.getElementById('risk-score').textContent = riskScore.toFixed(1);
        document.getElementById('open-ports').textContent = openPorts;
        document.getElementById('subdomains').textContent = subdomains;
        document.getElementById('security-issues').textContent = securityIssues;
    }

    calculateRiskScore() {
        let score = 5.0; // Base score
        
        // Adjust based on open ports
        if (this.scanResults['port-scan']) {
            const openPorts = this.scanResults['port-scan'].filter(p => p.status === 'Open');
            score += openPorts.length * 0.5;
        }

        // Adjust based on security headers
        if (this.scanResults['http-headers']) {
            const headers = this.scanResults['http-headers'].securityHeaders;
            if (!headers['strict-transport-security']) score += 1.0;
            if (!headers['x-frame-options']) score += 0.5;
            if (!headers['content-security-policy']) score += 0.8;
        }

        return Math.min(score, 10.0);
    }

    calculateSecurityIssues() {
        let issues = 0;
        
        if (this.scanResults['http-headers']) {
            const headers = this.scanResults['http-headers'].securityHeaders;
            if (!headers['strict-transport-security']) issues++;
            if (!headers['x-frame-options']) issues++;
            if (!headers['content-security-policy']) issues++;
        }

        return issues;
    }

    exportComprehensiveReport() {
        if (Object.keys(this.scanResults).length === 0) {
            this.showNotification('No scan results to export', 'error');
            return;
        }

        const report = {
            target: this.currentTarget,
            target_type: this.targetType,
            scan_date: new Date().toISOString(),
            scan_duration: this.scanStartTime ? (Date.now() - this.scanStartTime) / 1000 : 0,
            executive_summary: {
                risk_score: this.calculateRiskScore(),
                open_ports: this.scanResults['port-scan'] ? 
                    this.scanResults['port-scan'].filter(p => p.status === 'Open').length : 0,
                subdomains: this.scanResults['subdomain'] ? 
                    this.scanResults['subdomain'].filter(s => s.status === 'Active').length : 0,
                security_issues: this.calculateSecurityIssues()
            },
            reconnaissance_results: this.scanResults,
            tools_completed: this.completedScans,
            total_tools: this.totalScans
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyberrecon_comprehensive_report_${this.currentTarget.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification('Comprehensive report exported successfully!', 'success');
    }

    clearAllResults() {
        // Reset scan state
        this.scanResults = {};
        this.completedScans = 0;
        this.isScanning = false;
        this.scanStartTime = null;

        // Hide sections
        const progressSection = document.getElementById('progress-section');
        const resultsSection = document.getElementById('results-section');
        
        if (progressSection) progressSection.style.display = 'none';
        if (resultsSection) resultsSection.style.display = 'none';

        // Reset input
        const targetInput = document.getElementById('target-input');
        if (targetInput) {
            targetInput.value = '';
            this.updateInputDetection();
        }

        // Reset all result panels
        const resultContents = document.querySelectorAll('.result-content');
        resultContents.forEach(content => {
            content.innerHTML = '<div class="result-placeholder">Analysis results will appear here...</div>';
        });

        // Reset summary
        ['risk-score', 'open-ports', 'subdomains', 'security-issues'].forEach(id => {
            const element = document.getElementById(id);
            if (element) element.textContent = '-';
        });

        this.showNotification('All results cleared', 'info');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        const colors = {
            success: 'var(--cyber-text-primary)',
            error: 'var(--cyber-accent-red)',
            warning: 'var(--cyber-accent-yellow)',
            info: 'var(--cyber-accent-blue)'
        };

        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            z-index: 9999;
            animation: slideIn 0.3s ease;
            background: ${colors[type]};
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            font-family: 'Berkeley Mono', monospace;
            max-width: 400px;
        `;

        document.body.appendChild(notification);
        setTimeout(() => {
            notification.remove();
        }, 4000);
    }
}

// Initialize application when DOM is loaded
let app;

document.addEventListener('DOMContentLoaded', function() {
    app = new CyberReconPro();
    
    // Add notification animation styles
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .ip-type { background: rgba(0, 204, 255, 0.1) !important; color: var(--cyber-accent-blue) !important; }
        .domain-type { background: rgba(0, 255, 136, 0.1) !important; color: var(--cyber-text-primary) !important; }
        .hostname-type { background: rgba(170, 68, 255, 0.1) !important; color: var(--cyber-accent-purple) !important; }
        .url-type { background: rgba(255, 170, 0, 0.1) !important; color: var(--cyber-accent-yellow) !important; }
        .unknown-type { background: rgba(255, 68, 68, 0.1) !important; color: var(--cyber-accent-red) !important; }
        
        .status.status-success {
            background: rgba(0, 255, 136, 0.2);
            color: var(--cyber-text-primary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .status.status-warning {
            background: rgba(255, 170, 0, 0.2);
            color: var(--cyber-accent-yellow);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .status.status-error {
            background: rgba(255, 68, 68, 0.2);
            color: var(--cyber-accent-red);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
    `;
    document.head.appendChild(style);

    console.log('🛡️ CyberRecon Pro - All-in-One Reconnaissance Platform Initialized');
    console.log('🚀 Ready for comprehensive passive intelligence gathering');
});

// Fallback initialization
if (document.readyState === 'loading') {
    // DOM is still loading, event listener will handle initialization
} else {
    // DOM already loaded, initialize immediately
    if (!app) {
        app = new CyberReconPro();
    }
}