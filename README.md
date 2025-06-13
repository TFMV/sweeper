# 🛡️ SWEEPER

## The Ultimate Development Environment Security & Cleanup Tool

**Sweeper Fortress** is a bulletproof, enterprise-grade security auditing and cleanup tool designed for developers, security professionals, and system administrators who demand excellence. This isn't just another cleanup script—it's a comprehensive security fortress that protects your development environment while optimizing performance.

> **🚀 LATEST UPDATE**: Now includes 27+ new security audit functions, 15 additional package managers, enterprise-grade reporting, and comprehensive threat detection capabilities!

---

## 🚀 **ENTERPRISE-GRADE FEATURES**

### 🔐 **Advanced Security Arsenal**

- **Multi-Platform Support**: Linux, macOS, Windows/WSL
- **Advanced Persistent Threat (APT) Detection**
- **Real-time Rootkit & Malware Detection**
- **Cryptocurrency Mining Detection**
- **Memory Forensics & Behavioral Analysis**
- **Network Security Assessment**
- **Container Escape Detection**
- **Supply Chain Security Validation**
- **Zero-Trust Security Model Implementation**
- **🆕 Firmware/BIOS Verification** (Linux with fwupdmgr)
- **🆕 Process Ancestry & Anomaly Detection**
- **🆕 Login Audit with Brute-force Detection**
- **🆕 Security Baseline Enforcement with Lynis Scoring**

### 🧹 **Comprehensive Cleanup Capabilities**

- **25+ Package Managers**: pip, npm, yarn, cargo, go, maven, gradle, composer, nuget, cocoapods, conda, flatpak, snap, apk, pacman, yay, zypper, shards, dart, bazel, and more
- **Docker/Podman/Containerd Ecosystem Optimization**
- **Browser Data & Privacy Cleanup**
- **System Cache & Log Management**
- **Filesystem Integrity Auditing**
- **Certificate Lifecycle Management**
- **🆕 Database Engine Cleanup** (PostgreSQL, MySQL, Redis, MongoDB)
- **🆕 Orphaned Systemd Services Detection**
- **🆕 Temporary Users & Dev Accounts Audit**

### 📊 **Professional Reporting & Compliance**

- **Multiple Report Formats**: HTML, JSON, XML, PDF, Text
- **SIEM Integration**: Splunk, ELK, QRadar compatible
- **Real-time Notifications**: Webhook, Slack, Email alerts
- **Compliance Reporting**: SOC2, ISO27001, NIST frameworks
- **Executive Summary Reports**
- **Risk Scoring with CVSS Integration**
- **🆕 Prometheus/OpenTelemetry Metrics Export**
- **🆕 Trend Analysis & Historical Comparison**
- **🆕 Filesystem Bloat Reporting**

### 🍎 **macOS Security Specialization**

- **TCC (Transparency, Consent, and Control) Auditing**
- **LaunchAgents/LaunchDaemons Security Analysis**
- **Keychain Security Assessment**
- **System Integrity Protection (SIP) Monitoring**
- **Gatekeeper & XProtect Integration**
- **FileVault & Firewall Status Monitoring**
- **Wi-Fi Security Assessment**
- **Quarantine & Extended Attributes Analysis**

### 🛠️ **Operational Excellence**

- **🆕 Self-Update Mechanism** with integrity verification
- **🆕 Modular Plugin System** for extensibility
- **🆕 Bash Version Compatibility Checking**
- **🆕 Enhanced Error Handling & Security**
- **Cross-Platform Optimization**
- **Parallel Processing & Resource Management**

---

## 🎯 **CLEANUP LEVELS**

### **Basic Level** 🟢

Essential cleanup for daily maintenance:

- Package manager cache clearing (25+ managers)
- Temporary file cleanup
- Core dump removal
- User cache directory optimization

### **Standard Level** 🟡

Comprehensive cleanup for regular maintenance:

- All Basic level operations
- Docker system cleanup and optimization
- System log rotation and management
- Application-specific log cleanup
- Browser cache management

### **Deep Level** 🟠

Advanced security auditing and optimization:

- All Standard level operations
- **Complete Security Audit Suite**
- Rootkit and malware detection
- Network security assessment
- Filesystem integrity monitoring
- Certificate validation
- System hardening analysis
- Performance optimization
- **🆕 Firmware/BIOS verification**
- **🆕 Process ancestry analysis**
- **🆕 Login security audit**
- **🆕 Orphaned services detection**

### **Nuclear Level** 🔴 **[NEW]**

Maximum security and aggressive cleanup:

- All Deep level operations
- **Advanced Malware Detection**
- Cryptocurrency mining detection
- Memory forensics analysis
- Behavioral threat analysis
- YARA rule scanning
- **Nuclear-level cache/log purging**
- Complete browser history elimination
- **🆕 Temporary account cleanup**
- **🆕 Database engine optimization**

---

## 🛠️ **INSTALLATION & USAGE**

### **Quick Start**

```bash
# Make executable
chmod +x sweeper.sh

# Standard cleanup
./sweeper.sh

# Deep security audit
./sweeper.sh --level=deep

# Nuclear cleanup with stealth mode
./sweeper.sh --level=nuclear --stealth

# Dry run to preview actions
./sweeper.sh --dry-run --verbose

# Self-update to latest version
./sweeper.sh --self-update
```

### **Advanced Usage Examples**

```bash
# Enterprise security audit with reporting
./sweeper.sh --level=deep --report-format=html --webhook=https://your-webhook.com

# Paranoid mode with auto-remediation
./sweeper.sh --level=nuclear --paranoid --auto-remediate

# Compliance audit for SOC2
./sweeper.sh --level=deep --compliance=soc2 --report-format=json

# Stealth operation with Slack notifications
./sweeper.sh --level=deep --stealth --slack=https://hooks.slack.com/your-webhook

# Skip specific components
./sweeper.sh --level=deep --skip-docker --skip-network --skip-malware

# Custom configuration with metrics export
./sweeper.sh --config=enterprise.conf --export-metrics=/var/lib/prometheus/sweeper.prom

# Filesystem bloat analysis
./sweeper.sh --bloat-report

# CI/CD Integration
./sweeper.sh --level=standard --no-confirm --stealth --export-metrics=/tmp/metrics.prom
```

---

## ⚙️ **CONFIGURATION OPTIONS**

### **Command Line Arguments**

| Option | Description | Example |
|--------|-------------|---------|
| `--level=LEVEL` | Cleanup level: basic, standard, deep, nuclear | `--level=deep` |
| `--dry-run` | Preview actions without executing | `--dry-run` |
| `--skip-docker` | Skip Docker cleanup operations | `--skip-docker` |
| `--skip-security` | Skip security audit operations | `--skip-security` |
| `--skip-network` | **[NEW]** Skip network security auditing | `--skip-network` |
| `--skip-malware` | **[NEW]** Skip malware detection | `--skip-malware` |
| `--no-confirm` | **[NEW]** Non-interactive mode | `--no-confirm` |
| `--paranoid` | **[NEW]** Enhanced security checks | `--paranoid` |
| `--stealth` | **[NEW]** Minimal output mode | `--stealth` |
| `--auto-remediate` | **[NEW]** Automatic threat remediation | `--auto-remediate` |
| `--compliance=TYPE` | **[NEW]** Compliance framework | `--compliance=soc2` |
| `--webhook=URL` | **[NEW]** Webhook notification URL | `--webhook=https://...` |
| `--email=ADDRESS` | **[NEW]** Email alert address | `--email=admin@company.com` |
| `--slack=URL` | **[NEW]** Slack webhook URL | `--slack=https://hooks.slack.com/...` |
| `--report-format=FORMAT` | **[NEW]** Report format: text, json, html, xml, pdf | `--report-format=html` |
| `--export-metrics=FILE` | **[NEW]** Export Prometheus metrics | `--export-metrics=/tmp/metrics.prom` |
| `--bloat-report` | **[NEW]** Generate filesystem bloat analysis | `--bloat-report` |
| `--self-update` | **[NEW]** Update script from repository | `--self-update` |
| `--config=FILE` | Use custom configuration file | `--config=enterprise.conf` |
| `--log-file=FILE` | Custom log file location | `--log-file=/var/log/sweeper.log` |
| `--verbose` | Detailed output | `--verbose` |
| `--version` | Show version information | `--version` |

### **Configuration File (sweeper.conf)**

```bash
# Basic Settings
CLEANUP_LEVEL="deep"
SKIP_DOCKER=false
VERBOSE=true
PARANOID_MODE=true

# Security Settings
AUTO_INSTALL_SECURITY_TOOLS=true
MAX_SECURITY_SCAN_TIME=3600
SUSPICIOUS_PORTS="6667 6668 6669 1337 31337 4444 5555"
AUTO_REMEDIATE=false
THREAT_INTEL=true

# Notification Settings
WEBHOOK_URL="https://your-webhook.com/alerts"
EMAIL_ALERTS="security@company.com"
SLACK_WEBHOOK="https://hooks.slack.com/your-webhook"

# Cleanup Thresholds
TEMP_FILE_AGE=7
LOG_FILE_AGE=30
CERT_EXPIRY_WARNING_DAYS=30
MAX_CONCURRENT_SCANS=4

# Reporting
GENERATE_REPORT=true
REPORT_FORMAT="html"
COMPLIANCE_MODE="soc2"
```

---

## 🔍 **SECURITY FEATURES DEEP DIVE**

### **🆕 Enhanced Security Auditing**

#### **Firmware/BIOS Verification (Linux)**

- **fwupdmgr integration**: Lists firmware devices and available updates
- **UEFI Secure Boot verification**: Beyond basic efivars presence checking
- **Setup Mode detection**: Identifies potentially insecure boot states
- **Legacy BIOS vs UEFI detection**: Comprehensive boot security analysis

#### **Process Ancestry & Anomaly Detection**

- **Process tree analysis**: Uses `pstree` for comprehensive process relationships
- **Suspicious pattern detection**:
  - `cron → curl/wget` (potential backdoor installation)
  - `dbus → bash` (privilege escalation attempts)
  - `systemd → nc` (network backdoor establishment)
  - `init → python -c` (code injection attacks)
- **Orphaned process identification**: Detects processes with unusual parent relationships
- **Location-based analysis**: Flags processes running from `/tmp`, `/var/tmp`, `/dev/shm`

#### **Login Security Audit**

- **Recent login analysis**: `last -10` for successful login tracking
- **Per-user login history**: `lastlog` integration for account activity
- **Active session monitoring**: `who -a` for current user sessions
- **Failed login detection**: `/var/log/auth.log` and `journalctl` analysis
- **Brute-force pattern recognition**: Automatic threat scoring for high failure rates

#### **Security Baseline Enforcement**

- **Lynis integration with scoring**: Parses hardening index and enforces minimum scores
- **Configurable thresholds**: Default 70% minimum security score
- **Automatic recommendations**: Extracts and displays top security suggestions
- **Action triggers**: Alerts and remediation for below-threshold scores

### **Rootkit & Malware Detection**

- **chkrootkit**: System rootkit detection
- **rkhunter**: Comprehensive rootkit hunting
- **ClamAV**: Antivirus scanning of critical directories
- **Custom YARA Rules**: Malware signature detection
- **Behavioral Analysis**: Suspicious process monitoring
- **Memory Forensics**: Rootkit signature analysis
- **🆕 Cryptocurrency Mining Detection**: Process and network pattern analysis

### **Network Security Assessment**

- **Port Scanning**: Suspicious port detection
- **Connection Analysis**: Unusual network activity monitoring
- **DNS Security**: Configuration and poisoning detection
- **Firewall Auditing**: Configuration validation
- **Wi-Fi Security**: Rogue network detection (macOS)
- **Reverse DNS Lookups**: IP reputation checking

### **Filesystem Security**

- **World-Writable Files**: Permission vulnerability detection
- **Suspicious Symlinks**: Malicious link detection
- **Dotfile Injection**: Shell configuration tampering
- **File Integrity**: AIDE/Tripwire integration
- **Hidden File Analysis**: Steganography detection
- **Large File Auditing**: Data exfiltration prevention

### **Container Security**

- **Docker Daemon Security**: Configuration auditing
- **Privileged Container Detection**: Risk assessment
- **Image Vulnerability Scanning**: Trivy integration
- **Container Escape Detection**: Runtime security
- **Registry Security**: Supply chain validation

---

## 🧼 **ENHANCED CLEANUP CAPABILITIES**

### **🆕 Database Engine Cleanup**

- **PostgreSQL**: `VACUUM` operations, WAL file cleanup
- **MySQL/MariaDB**: Binary log purging, slow query log cleanup
- **Redis**: `FLUSHALL` operations for cache clearing
- **MongoDB**: Journal file cleanup, orphaned data removal

### **🆕 Complete Package Ecosystem Support**

**New Package Managers Added**:

- **Alpine Linux**: `apk cache clean`
- **Arch Linux**: `pacman -Sc`, `yay -Sc`
- **SUSE**: `zypper clean --all`
- **Flatpak**: `flatpak remote prune`
- **Crystal**: `shards` cache cleanup
- **Dart**: `dart pub cache clean`
- **Bazel**: `bazel clean --expunge`

**Enhanced Existing Support**:

- **npm**: Global cache cleanup, `_cacache` removal
- **Yarn**: Global cache directory cleanup
- **Cargo**: Git pack file cleanup, enhanced registry cleaning
- **Maven**: Selective artifact cleanup, metadata file removal
- **Gradle**: Lock file and temporary file cleanup

### **🆕 Orphaned Systemd Services Detection**

- **Service-Process Correlation**: Identifies enabled services without running processes
- **Broken Unit Detection**: Finds failed `.mount`, `.socket`, `.timer` units
- **State Monitoring**: Tracks service health and process relationships

### **🆕 Temporary Users & Dev Accounts Audit**

- **Homeless Users**: Identifies users with UID > 1000 without home directories
- **Inactive Accounts**: Detects accounts without recent login activity (90+ days)
- **Development Patterns**: Flags test/demo/staging/temp accounts
- **Security Hygiene**: Reports unused and potentially risky accounts

---

## 📊 **REPORTING & COMPLIANCE**

### **🆕 Prometheus/OpenTelemetry Integration**

**Exported Metrics**:

```prometheus
# HELP sweeper_warnings_total Total number of warnings detected
sweeper_warnings_total 5

# HELP sweeper_errors_total Total number of errors encountered
sweeper_errors_total 0

# HELP sweeper_threats_total Total number of threats detected
sweeper_threats_total 2

# HELP sweeper_files_cleaned_total Total number of files cleaned
sweeper_files_cleaned_total 1247

# HELP sweeper_bytes_freed_total Total bytes freed during cleanup
sweeper_bytes_freed_total 2147483648

# HELP sweeper_last_run_timestamp Unix timestamp of last run
sweeper_last_run_timestamp 1703875200
```

**Usage**: `--export-metrics=/var/lib/prometheus/sweeper.prom`

### **🆕 Filesystem Bloat Analysis**

**Automatic Reports Include**:

- Top 10 largest directories system-wide
- Top 10 largest files in home directory
- Disk usage by filesystem (excluding tmpfs)
- Storage optimization recommendations

**Usage**: `--bloat-report` or automatic in deep/nuclear modes

### **Report Formats**

#### **HTML Report**

- Interactive dashboard with charts
- Color-coded threat levels
- Executive summary
- Detailed findings with remediation steps

#### **JSON Report**

- Machine-readable format
- SIEM integration ready
- API consumption friendly
- Structured threat intelligence
- **🆕 Historical comparison data**
- **🆕 Trend analysis metrics**

#### **XML Report**

- Enterprise system integration
- Compliance framework compatible
- Audit trail documentation

### **Compliance Frameworks**

- **SOC 2**: Security controls validation
- **ISO 27001**: Information security management
- **NIST**: Cybersecurity framework alignment
- **PCI DSS**: Payment card industry standards

---

## 🚨 **THREAT DETECTION CAPABILITIES**

### **Advanced Persistent Threats (APT)**

- **Lateral Movement Detection**: Unusual network patterns
- **Persistence Mechanism Analysis**: Startup/cron job auditing
- **Data Staging Detection**: Large file accumulation
- **Command & Control Detection**: Suspicious network connections

### **🆕 Enhanced Cryptocurrency Mining Detection**

- **Process Detection**: Known mining software identification (xmrig, cpuminer, cgminer, etc.)
- **CPU Usage Analysis**: High-consumption process monitoring with safe comparison
- **Network Pattern Analysis**: Mining pool connections
- **GPU Utilization Monitoring**: Hardware abuse detection

### **Supply Chain Attacks**

- **Package Integrity Verification**: Checksum validation
- **Dependency Analysis**: Malicious package detection
- **Code Signing Verification**: Certificate validation
- **Repository Security**: Source authenticity checking

---

## 🔧 **PLATFORM-SPECIFIC FEATURES**

### **macOS Specialization**

```bash
# TCC Database Analysis
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access;"

# LaunchAgent Security Scan
find ~/Library/LaunchAgents -name "*.plist" -exec plutil -p {} \;

# Keychain Security Audit
security list-keychains
security dump-keychain | grep -E "(ssh|ftp|password)"

# System Extension Analysis
systemextensionsctl list
kextstat | grep -v com.apple
```

### **Linux Hardening**

```bash
# SELinux/AppArmor Status
getenforce
aa-status

# Kernel Security Features
cat /proc/sys/kernel/randomize_va_space  # ASLR
grep nx /proc/cpuinfo                    # NX bit

# Service Security Analysis
systemctl list-units --type=service --state=active

# 🆕 Firmware Security
fwupdmgr get-devices
fwupdmgr get-updates
```

---

## 🎛️ **ADVANCED CONFIGURATION**

### **Enterprise Deployment**

```bash
# Centralized configuration
export SWEEPER_CONFIG_URL="https://config.company.com/sweeper.conf"
export SWEEPER_REPORT_ENDPOINT="https://siem.company.com/api/reports"
export SWEEPER_ALERT_WEBHOOK="https://alerts.company.com/webhook"

# Automated deployment
./sweeper.sh --level=deep --no-confirm --stealth \
  --webhook="$SWEEPER_ALERT_WEBHOOK" \
  --report-format=json \
  --export-metrics=/var/lib/prometheus/sweeper.prom
```

### **CI/CD Integration**

```yaml
# GitHub Actions Example
- name: Security Audit
  run: |
    chmod +x sweeper.sh
    ./sweeper.sh --level=deep --no-confirm --report-format=json \
      --export-metrics=/tmp/sweeper_metrics.prom
    
- name: Upload Security Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: reports/

- name: Upload Metrics
  uses: actions/upload-artifact@v2
  with:
    name: prometheus-metrics
    path: /tmp/sweeper_metrics.prom
```

### **🆕 Plugin System**

```bash
# Create plugin directory
mkdir -p plugins

# Example plugin: plugins/custom_security.sh
#!/bin/bash
custom_security_check() {
    info "Running custom security check..."
    # Your custom security logic here
}

# Plugin will be automatically loaded
./sweeper.sh --level=deep
```

### **Monitoring Integration**

```bash
# Prometheus metrics export
./sweeper.sh --level=deep --export-metrics=/var/lib/prometheus/sweeper.prom

# Grafana dashboard integration
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @sweeper_dashboard.json
```

---

## 🛡️ **SECURITY BEST PRACTICES**

### **Operational Security**

1. **Never run as root** unless absolutely necessary
2. **Use stealth mode** in production environments
3. **Configure webhook alerts** for immediate threat notification
4. **Regular scheduling** with cron for continuous monitoring
5. **Backup quarantined files** before deletion
6. **🆕 Use plugin system** for custom security checks
7. **🆕 Enable Prometheus metrics** for monitoring
8. **🆕 Set up compliance reporting** for audit trails

### **Threat Response**

1. **Immediate isolation** of detected threats
2. **Forensic preservation** of evidence
3. **Incident documentation** with detailed reports
4. **Stakeholder notification** via configured channels
5. **Remediation tracking** with follow-up scans
6. **🆕 Automated remediation** for known threat patterns
7. **🆕 Historical analysis** for trend identification

---

## 📈 **PERFORMANCE OPTIMIZATION**

### **Resource Management**

- **Concurrent scanning**: Configurable thread limits (MAX_CONCURRENT_SCANS)
- **Memory optimization**: Efficient file processing
- **Disk I/O optimization**: Smart caching strategies
- **Network throttling**: Bandwidth-aware operations
- **🆕 Timeout protection**: Prevents long-running operations from hanging

### **Scalability Features**

- **Distributed scanning**: Multi-node deployment capability
- **Load balancing**: Work distribution algorithms
- **Result aggregation**: Centralized reporting
- **Cache sharing**: Distributed intelligence
- **🆕 Plugin architecture**: Extensible without core modification

---

## 🔄 **AUTOMATION & SCHEDULING**

### **Cron Integration**

```bash
# Daily security audit
0 2 * * * /path/to/sweeper.sh --level=standard --no-confirm --stealth

# Weekly deep scan with reporting
0 3 * * 0 /path/to/sweeper.sh --level=deep --no-confirm --report-format=html \
  --export-metrics=/var/lib/prometheus/sweeper.prom

# Monthly nuclear cleanup
0 4 1 * * /path/to/sweeper.sh --level=nuclear --no-confirm --paranoid
```

### **Systemd Service**

```ini
[Unit]
Description=Sweeper Fortress Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sweeper.sh --level=deep --no-confirm --stealth \
  --export-metrics=/var/lib/prometheus/sweeper.prom
User=sweeper
Group=sweeper

[Install]
WantedBy=multi-user.target
```

### **🆕 Self-Maintenance**

```bash
# Automatic updates
./sweeper.sh --self-update

# Scheduled self-update (weekly)
0 1 * * 0 /path/to/sweeper.sh --self-update
```

---

## 🆘 **TROUBLESHOOTING**

### **Common Issues**

#### **Permission Denied**

```bash
# Solution: Check file permissions
chmod +x sweeper.sh
sudo chown $USER:$USER sweeper.sh
```

#### **Bash Version Compatibility**

```bash
# Check Bash version
bash --version

# Install newer Bash (macOS)
brew install bash

# Use newer Bash
/opt/homebrew/bin/bash ./sweeper.sh --level=deep
```

#### **Missing Dependencies**

```bash
# Auto-install security tools
export AUTO_INSTALL_SECURITY_TOOLS=true
./sweeper.sh --level=deep
```

#### **High Resource Usage**

```bash
# Limit concurrent operations
export MAX_CONCURRENT_SCANS=2
./sweeper.sh --level=deep
```

### **Debug Mode**

```bash
# Enable maximum verbosity
./sweeper.sh --level=deep --verbose --dry-run

# Check log files
tail -f /tmp/sweeper-fortress-*.log
tail -f /tmp/sweeper-fortress-*.log.json

# Export metrics for analysis
./sweeper.sh --export-metrics=/tmp/debug_metrics.prom
```

---

## 🤝 **CONTRIBUTING**

We welcome contributions from security professionals and developers worldwide!

### **Development Setup**

```bash
git clone https://github.com/TFMV/sweeper.git
cd sweeper
chmod +x sweeper.sh
./sweeper.sh --level=basic --dry-run --verbose
```

### **Plugin Development**

```bash
# Create a new plugin
mkdir -p plugins
cat > plugins/my_security_check.sh << 'EOF'
#!/bin/bash
my_custom_check() {
    info "Running my custom security check..."
    # Your security logic here
}
EOF

# Test the plugin
./sweeper.sh --level=deep --verbose
```

### **Testing Framework**

```bash
# Unit tests
./tests/run_unit_tests.sh

# Integration tests
./tests/run_integration_tests.sh

# Security tests
./tests/run_security_tests.sh
```

---

## 📜 **LICENSE**

MIT
