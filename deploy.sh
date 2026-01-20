#!/bin/bash
# EasyLic Production Deployment Script

set -e

echo "=== EasyLic Production Deployment ==="

# Configuration
APP_NAME="easylic"
APP_DIR="/opt/$APP_NAME"
VENV_DIR="$APP_DIR/venv"
USER_NAME="$APP_NAME"
SERVICE_FILE="/etc/systemd/system/$APP_NAME.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Create application user
if ! id "$USER_NAME" &>/dev/null; then
    log_info "Creating user $USER_NAME"
    useradd --system --shell /bin/bash --home-dir "$APP_DIR" --create-home "$USER_NAME"
else
    log_info "User $USER_NAME already exists"
fi

# Create application directory
log_info "Creating application directory $APP_DIR"
mkdir -p "$APP_DIR"
chown "$USER_NAME:$USER_NAME" "$APP_DIR"

# Install Python dependencies
log_info "Setting up Python virtual environment"
su - "$USER_NAME" -c "python3 -m venv $VENV_DIR"
su - "$USER_NAME" -c "$VENV_DIR/bin/pip install --upgrade pip"

# Copy application files
log_info "Copying application files"
cp -r . "$APP_DIR/"
chown -R "$USER_NAME:$USER_NAME" "$APP_DIR"

# Install Python package
log_info "Installing Python package"
su - "$USER_NAME" -c "cd $APP_DIR && $VENV_DIR/bin/pip install -e ."

# Generate server keys
log_info "Generating server keys"
su - "$USER_NAME" -c "cd $APP_DIR && $VENV_DIR/bin/easylic keygen"

# Create admin password file
if [[ ! -f /etc/easylic/admin_password ]]; then
    log_info "Creating admin password file"
    mkdir -p /etc/easylic
    echo "admin123" > /etc/easylic/admin_password
    chmod 600 /etc/easylic/admin_password
    log_warn "Default admin password set. Change it in /etc/easylic/admin_password"
fi

# Install systemd service
log_info "Installing systemd service"
cp "systemd/$APP_NAME.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$APP_NAME"

# Start service
log_info "Starting $APP_NAME service"
systemctl start "$APP_NAME"

# Check service status
sleep 5
if systemctl is-active --quiet "$APP_NAME"; then
    log_info "Service started successfully"
    systemctl status "$APP_NAME" --no-pager -l
else
    log_error "Service failed to start"
    systemctl status "$APP_NAME" --no-pager -l
    exit 1
fi

log_info "=== Deployment completed successfully ==="
log_info "Service: $APP_NAME"
log_info "Status: systemctl status $APP_NAME"
log_info "Logs: journalctl -u $APP_NAME -f"
log_info "Web interface: http://localhost:8000"