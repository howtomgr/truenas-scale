# TrueNAS SCALE Installation Guide

TrueNAS SCALE is a free and open-source Storage Solution. An open-source hyper-converged storage solution

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 443 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 443 (default truenas-scale port)
  - Firewall rules configured
- **Dependencies**:
  - debian-base, zfs, kubernetes
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install truenas-scale
sudo dnf install -y truenas-scale debian-base, zfs, kubernetes

# Enable and start service
sudo systemctl enable --now middlewared

# Configure firewall
sudo firewall-cmd --permanent --add-service=truenas-scale || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
truenas-scale --version || systemctl status middlewared
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install truenas-scale
sudo apt install -y truenas-scale debian-base, zfs, kubernetes

# Enable and start service
sudo systemctl enable --now middlewared

# Configure firewall
sudo ufw allow 443

# Verify installation
truenas-scale --version || systemctl status middlewared
```

### Arch Linux

```bash
# Install truenas-scale
sudo pacman -S truenas-scale

# Enable and start service
sudo systemctl enable --now middlewared

# Verify installation
truenas-scale --version || systemctl status middlewared
```

### Alpine Linux

```bash
# Install truenas-scale
apk add --no-cache truenas-scale

# Enable and start service
rc-update add middlewared default
rc-service middlewared start

# Verify installation
truenas-scale --version || rc-service middlewared status
```

### openSUSE/SLES

```bash
# Install truenas-scale
sudo zypper install -y truenas-scale debian-base, zfs, kubernetes

# Enable and start service
sudo systemctl enable --now middlewared

# Configure firewall
sudo firewall-cmd --permanent --add-service=truenas-scale || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
truenas-scale --version || systemctl status middlewared
```

### macOS

```bash
# Using Homebrew
brew install truenas-scale

# Start service
brew services start truenas-scale

# Verify installation
truenas-scale --version
```

### FreeBSD

```bash
# Using pkg
pkg install truenas-scale

# Enable in rc.conf
echo 'middlewared_enable="YES"' >> /etc/rc.conf

# Start service
service middlewared start

# Verify installation
truenas-scale --version || service middlewared status
```

### Windows

```powershell
# Using Chocolatey
choco install truenas-scale

# Or using Scoop
scoop install truenas-scale

# Verify installation
truenas-scale --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /etc/middleware

# Set up basic configuration
sudo tee /etc/middleware/truenas-scale.conf << 'EOF'
# TrueNAS SCALE Configuration
zfs_arc_max = 8G
EOF

# Set appropriate permissions
sudo chown -R truenas-scale:truenas-scale /etc/middleware || \
  sudo chown -R $(whoami):$(whoami) /etc/middleware

# Test configuration
sudo truenas-scale --test || sudo middlewared configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false truenas-scale || true

# Secure configuration files
sudo chmod 750 /etc/middleware
sudo chmod 640 /etc/middleware/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable middlewared

# Start service
sudo systemctl start middlewared

# Stop service
sudo systemctl stop middlewared

# Restart service
sudo systemctl restart middlewared

# Reload configuration
sudo systemctl reload middlewared

# Check status
sudo systemctl status middlewared

# View logs
sudo journalctl -u middlewared -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add middlewared default

# Start service
rc-service middlewared start

# Stop service
rc-service middlewared stop

# Restart service
rc-service middlewared restart

# Check status
rc-service middlewared status

# View logs
tail -f /var/log/middlewared/middlewared.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'middlewared_enable="YES"' >> /etc/rc.conf

# Start service
service middlewared start

# Stop service
service middlewared stop

# Restart service
service middlewared restart

# Check status
service middlewared status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start truenas-scale
brew services stop truenas-scale
brew services restart truenas-scale

# Check status
brew services list | grep truenas-scale

# View logs
tail -f $(brew --prefix)/var/log/truenas-scale.log
```

### Windows Service Manager

```powershell
# Start service
net start middlewared

# Stop service
net stop middlewared

# Using PowerShell
Start-Service middlewared
Stop-Service middlewared
Restart-Service middlewared

# Check status
Get-Service middlewared

# Set to automatic startup
Set-Service middlewared -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /etc/middleware/truenas-scale.conf << 'EOF'
# Performance tuning
zfs_arc_max = 8G
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart middlewared
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream truenas-scale_backend {
    server 127.0.0.1:443;
    keepalive 32;
}

server {
    listen 80;
    server_name truenas-scale.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name truenas-scale.example.com;

    ssl_certificate /etc/ssl/certs/truenas-scale.crt;
    ssl_certificate_key /etc/ssl/private/truenas-scale.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://truenas-scale_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName truenas-scale.example.com
    Redirect permanent / https://truenas-scale.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName truenas-scale.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/truenas-scale.crt
    SSLCertificateKeyFile /etc/ssl/private/truenas-scale.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:443/
        ProxyPassReverse http://127.0.0.1:443/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:443/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend truenas-scale_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/truenas-scale.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend truenas-scale_backend

backend truenas-scale_backend
    balance roundrobin
    option httpchk GET /health
    server truenas-scale1 127.0.0.1:443 check
```

### Caddy Configuration

```caddy
truenas-scale.example.com {
    reverse_proxy 127.0.0.1:443 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /etc/middleware truenas-scale || true

# Set ownership
sudo chown -R truenas-scale:truenas-scale /etc/middleware
sudo chown -R truenas-scale:truenas-scale /var/log/middlewared

# Set permissions
sudo chmod 750 /etc/middleware
sudo chmod 640 /etc/middleware/*
sudo chmod 750 /var/log/middlewared

# Configure firewall (UFW)
sudo ufw allow from any to any port 443 proto tcp comment "TrueNAS SCALE"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=truenas-scale
sudo firewall-cmd --permanent --service=truenas-scale --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=truenas-scale
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 443 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/truenas-scale.key \
    -out /etc/ssl/certs/truenas-scale.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=truenas-scale.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/truenas-scale.key
sudo chmod 644 /etc/ssl/certs/truenas-scale.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d truenas-scale.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/truenas-scale.conf
[truenas-scale]
enabled = true
port = 443
filter = truenas-scale
logpath = /var/log/middlewared/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/truenas-scale.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE truenas-scale_db;
CREATE USER truenas-scale_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE truenas-scale_db TO truenas-scale_user;
\q
EOF

# Configure connection in TrueNAS SCALE
echo "DATABASE_URL=postgresql://truenas-scale_user:secure_password_here@localhost/truenas-scale_db" | \
  sudo tee -a /etc/middleware/truenas-scale.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE truenas-scale_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'truenas-scale_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON truenas-scale_db.* TO 'truenas-scale_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://truenas-scale_user:secure_password_here@localhost/truenas-scale_db" | \
  sudo tee -a /etc/middleware/truenas-scale.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/truenas-scale
sudo chown truenas-scale:truenas-scale /var/lib/truenas-scale

# Initialize database
sudo -u truenas-scale truenas-scale init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
truenas-scale soft nofile 65535
truenas-scale hard nofile 65535
truenas-scale soft nproc 32768
truenas-scale hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /etc/middleware/performance.conf
# Performance configuration
zfs_arc_max = 8G

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart middlewared
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'truenas-scale'
    static_configs:
      - targets: ['localhost:443/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/truenas-scale-health

# Check if service is running
if ! systemctl is-active --quiet middlewared; then
    echo "CRITICAL: TrueNAS SCALE service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 443 2>/dev/null; then
    echo "CRITICAL: TrueNAS SCALE is not listening on port 443"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:443/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: TrueNAS SCALE is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/truenas-scale
/var/log/middlewared/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 truenas-scale truenas-scale
    postrotate
        systemctl reload middlewared > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/truenas-scale
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/truenas-scale-backup

BACKUP_DIR="/backup/truenas-scale"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/truenas-scale_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping TrueNAS SCALE service..."
systemctl stop middlewared

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /etc/middleware \
    /var/lib/truenas-scale \
    /var/log/middlewared

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump truenas-scale_db | gzip > "$BACKUP_DIR/truenas-scale_db_$DATE.sql.gz"
fi

# Start service
echo "Starting TrueNAS SCALE service..."
systemctl start middlewared

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/truenas-scale-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping TrueNAS SCALE service..."
systemctl stop middlewared

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql truenas-scale_db
fi

# Fix permissions
chown -R truenas-scale:truenas-scale /etc/middleware
chown -R truenas-scale:truenas-scale /var/lib/truenas-scale

# Start service
echo "Starting TrueNAS SCALE service..."
systemctl start middlewared

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status middlewared
sudo journalctl -u middlewared -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 443
sudo lsof -i :443

# Verify configuration
sudo truenas-scale --test || sudo middlewared configtest

# Check permissions
ls -la /etc/middleware
ls -la /var/log/middlewared
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep middlewared
curl -I http://localhost:443

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 443

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep truenas-scale
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep middlewared)
htop -p $(pgrep middlewared)

# Check for memory leaks
ps aux | grep middlewared
cat /proc/$(pgrep middlewared)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/middlewared/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U truenas-scale_user -d truenas-scale_db -c "SELECT 1;"
mysql -u truenas-scale_user -p truenas-scale_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /etc/middleware/truenas-scale.conf

# Restart with debug mode
sudo systemctl stop middlewared
sudo -u truenas-scale truenas-scale --debug

# Watch debug logs
tail -f /var/log/middlewared/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep middlewared) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/truenas-scale.pcap port 443
sudo tcpdump -r /tmp/truenas-scale.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep middlewared)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  truenas-scale:
    image: truenas-scale:truenas-scale
    container_name: truenas-scale
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/etc/middleware
      - ./data:/var/lib/truenas-scale
      - ./logs:/var/log/middlewared
    networks:
      - truenas-scale_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  truenas-scale_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# truenas-scale-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: truenas-scale
  labels:
    app: truenas-scale
spec:
  replicas: 1
  selector:
    matchLabels:
      app: truenas-scale
  template:
    metadata:
      labels:
        app: truenas-scale
    spec:
      containers:
      - name: truenas-scale
        image: truenas-scale:truenas-scale
        ports:
        - containerPort: 443
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /etc/middleware
        - name: data
          mountPath: /var/lib/truenas-scale
        livenessProbe:
          httpGet:
            path: /health
            port: 443
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 443
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: truenas-scale-config
      - name: data
        persistentVolumeClaim:
          claimName: truenas-scale-data
---
apiVersion: v1
kind: Service
metadata:
  name: truenas-scale
spec:
  selector:
    app: truenas-scale
  ports:
  - protocol: TCP
    port: 443
    targetPort: 443
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: truenas-scale-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# truenas-scale-playbook.yml
- name: Install and configure TrueNAS SCALE
  hosts: all
  become: yes
  vars:
    truenas-scale_version: latest
    truenas-scale_port: 443
    truenas-scale_config_dir: /etc/middleware
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - debian-base, zfs, kubernetes
        state: present
    
    - name: Install TrueNAS SCALE
      package:
        name: truenas-scale
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ truenas-scale_config_dir }}"
        state: directory
        owner: truenas-scale
        group: truenas-scale
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: truenas-scale.conf.j2
        dest: "{{ truenas-scale_config_dir }}/truenas-scale.conf"
        owner: truenas-scale
        group: truenas-scale
        mode: '0640'
      notify: restart truenas-scale
    
    - name: Start and enable service
      systemd:
        name: middlewared
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ truenas-scale_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart truenas-scale
      systemd:
        name: middlewared
        state: restarted
```

### Terraform Configuration

```hcl
# truenas-scale.tf
resource "aws_instance" "truenas-scale_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.truenas-scale.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install TrueNAS SCALE
    apt-get update
    apt-get install -y truenas-scale debian-base, zfs, kubernetes
    
    # Configure TrueNAS SCALE
    systemctl enable middlewared
    systemctl start middlewared
  EOF
  
  tags = {
    Name = "TrueNAS SCALE Server"
    Application = "TrueNAS SCALE"
  }
}

resource "aws_security_group" "truenas-scale" {
  name        = "truenas-scale-sg"
  description = "Security group for TrueNAS SCALE"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "TrueNAS SCALE Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update truenas-scale
sudo dnf update truenas-scale

# Debian/Ubuntu
sudo apt update
sudo apt upgrade truenas-scale

# Arch Linux
sudo pacman -Syu truenas-scale

# Alpine Linux
apk update
apk upgrade truenas-scale

# openSUSE
sudo zypper ref
sudo zypper update truenas-scale

# FreeBSD
pkg update
pkg upgrade truenas-scale

# Always backup before updates
/usr/local/bin/truenas-scale-backup

# Restart after updates
sudo systemctl restart middlewared
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log/middlewared -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze truenas-scale_db

# Check disk usage
df -h | grep -E "(/$|truenas-scale)"
du -sh /var/lib/truenas-scale

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u middlewared | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.truenas-scale.org/
- GitHub Repository: https://github.com/truenas-scale/truenas-scale
- Community Forum: https://forum.truenas-scale.org/
- Wiki: https://wiki.truenas-scale.org/
- Docker Hub: https://hub.docker.com/r/truenas-scale/truenas-scale
- Security Advisories: https://security.truenas-scale.org/
- Best Practices: https://docs.truenas-scale.org/best-practices
- API Documentation: https://api.truenas-scale.org/
- Comparison with FreeNAS, OpenMediaVault, Unraid, Proxmox: https://docs.truenas-scale.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
