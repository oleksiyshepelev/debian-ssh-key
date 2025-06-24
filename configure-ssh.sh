#!/usr/bin/env bash
# 02-configure-ssh.sh - Configuración segura de SSH

set -euo pipefail

# ─── Funciones de logging (heredadas) ──────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[1;34m'; CYAN='\033[1;36m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

step() { echo -e "\n${BLUE}▶️  $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
ok()   { echo -e "${GREEN}✅ $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

# ─── Verificaciones iniciales ──────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Este script debe ejecutarse como root"
    exit 1
fi

if [[ -z "${USERNAME:-}" ]]; then
    error "Variable USERNAME no definida"
    exit 1
fi

if [[ -z "${HOME_DIR:-}" ]]; then
    error "Variable HOME_DIR no definida"
    exit 1
fi

# ─── Verificar usuario ─────────────────────────────────────────
if ! getent passwd "$USERNAME" &>/dev/null; then
    error "Usuario '$USERNAME' no existe"
    exit 1
fi

if [[ "$USERNAME" == "root" ]]; then
    error "No se permite configurar SSH para root"
    exit 1
fi

# ─── Configurar directorio SSH ─────────────────────────────────
step "Configurando directorio SSH para $USERNAME..."

SSH_DIR="$HOME_DIR/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

# Crear directorio .ssh si no existe
if [[ ! -d "$SSH_DIR" ]]; then
    mkdir -p "$SSH_DIR"
    info "Directorio .ssh creado"
fi

# Crear archivo authorized_keys si no existe
if [[ ! -f "$AUTHORIZED_KEYS" ]]; then
    touch "$AUTHORIZED_KEYS"
    info "Archivo authorized_keys creado"
fi

# Configurar permisos correctos
chmod 700 "$SSH_DIR"
chmod 600 "$AUTHORIZED_KEYS"
chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

ok "Directorio SSH configurado con permisos seguros"

# ─── Obtener clave pública SSH ─────────────────────────────────
step "Configurando clave pública SSH..."

PUBLIC_KEY=""

# Si se especificó un archivo de clave
if [[ -n "${KEY_FILE:-}" ]]; then
    if [[ -f "$KEY_FILE" ]]; then
        PUBLIC_KEY=$(cat "$KEY_FILE")
        info "Clave pública leída desde $KEY_FILE"
    else
        error "Archivo de clave $KEY_FILE no encontrado"
        exit 1
    fi
fi

# Modo interactivo para obtener clave
if [[ -z "$PUBLIC_KEY" && "${INTERACTIVE:-true}" == "true" ]]; then
    echo
    info "Opciones para añadir clave pública SSH:"
    echo "1. Pegar clave directamente"
    echo "2. Especificar archivo de clave"
    echo "3. Saltar configuración de clave (PELIGROSO)"
    echo
    
    while true; do
        read -rp "Selecciona una opción (1-3): " option
        case $option in
            1)
                echo
                info "Pega tu clave pública SSH (una línea completa):"
                info "Ejemplo: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
                read -r PUBLIC_KEY
                if [[ -n "$PUBLIC_KEY" ]]; then
                    break
                else
                    warn "Clave vacía, inténtalo de nuevo"
                fi
                ;;
            2)
                read -rp "Ruta del archivo de clave pública: " key_path
                if [[ -f "$key_path" ]]; then
                    PUBLIC_KEY=$(cat "$key_path")
                    break
                else
                    warn "Archivo no encontrado: $key_path"
                fi
                ;;
            3)
                warn "Saltando configuración de clave SSH"
                warn "¡PELIGRO! El servidor quedará sin autenticación SSH configurada"
                break
                ;;
            *)
                warn "Opción inválida"
                ;;
        esac
    done
fi

# Validar y añadir clave pública
if [[ -n "$PUBLIC_KEY" ]]; then
    # Validar formato básico de clave SSH
    if [[ "$PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ssh-ecdsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\ [A-Za-z0-9+/]+ ]]; then
        # Verificar si la clave ya existe
        if grep -qF "$PUBLIC_KEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
            info "La clave SSH ya existe en authorized_keys"
        else
            echo "$PUBLIC_KEY" >> "$AUTHORIZED_KEYS"
            ok "Clave SSH añadida a authorized_keys"
        fi
        
        # Verificar que se añadió correctamente
        if grep -qF "$PUBLIC_KEY" "$AUTHORIZED_KEYS"; then
            ok "Clave SSH verificada en authorized_keys"
        else
            error "No se pudo verificar la clave en authorized_keys"
            exit 1
        fi
    else
        error "Formato de clave SSH inválido"
        error "Debe empezar con ssh-rsa, ssh-ed25519, etc."
        exit 1
    fi
fi

# ─── Configurar SSH daemon ─────────────────────────────────────
step "Configurando SSH daemon de forma segura..."

# Crear backup del archivo original
if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    info "Backup creado: /etc/ssh/sshd_config.backup"
fi

# Configuración SSH segura
info "Aplicando configuración SSH segura..."

# Función para actualizar configuración SSH
update_ssh_config() {
    local key="$1"
    local value="$2"
    local config_file="/etc/ssh/sshd_config"
    
    if grep -q "^#*${key}" "$config_file"; then
        sed -i "s/^#*${key}.*/${key} ${value}/" "$config_file"
    else
        echo "${key} ${value}" >> "$config_file"
    fi
}

# Aplicar configuraciones seguras
update_ssh_config "PasswordAuthentication" "no"
update_ssh_config "PermitRootLogin" "no"
update_ssh_config "PubkeyAuthentication" "yes"
update_ssh_config "AuthorizedKeysFile" ".ssh/authorized_keys"
update_ssh_config "PermitEmptyPasswords" "no"
update_ssh_config "MaxAuthTries" "3"
update_ssh_config "ClientAliveInterval" "300"
update_ssh_config "ClientAliveCountMax" "2"
update_ssh_config "Protocol" "2"

# Configuraciones adicionales de seguridad
cat >> /etc/ssh/sshd_config << 'EOF'

# Configuración adicional de seguridad
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
EOF

ok "Configuración SSH aplicada"

# ─── Validar configuración SSH ─────────────────────────────────
step "Validando configuración SSH..."

if sshd -t; then
    ok "Configuración SSH válida"
else
    error "Configuración SSH inválida"
    info "Restaurando backup..."
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    exit 1
fi

# ─── Preparar reinicio seguro de SSH ──────────────────────────
step "Preparando reinicio seguro de SSH..."

# Crear script de reinicio con verificación
cat > /tmp/restart_ssh_safe.sh << 'EOF'
#!/bin/bash
echo "Reiniciando SSH en 3 segundos..."
sleep 3
systemctl restart ssh
if systemctl is-active --quiet ssh; then
    echo "✅ SSH reiniciado correctamente"
else
    echo "❌ Error al reiniciar SSH, restaurando configuración..."
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    systemctl restart ssh
fi
EOF

chmod +x /tmp/restart_ssh_safe.sh

# Ejecutar en background para evitar cortar la conexión actual
info "Reiniciando SSH daemon..."
warn "¡ATENCIÓN! Verifica que puedes conectarte con la nueva configuración"

# Reiniciar SSH de forma segura
if /tmp/restart_ssh_safe.sh & then
    sleep 5
    if systemctl is-active --quiet ssh; then
        ok "SSH reiniciado correctamente"
    else
        error "Error al reiniciar SSH"
        exit 1
    fi
fi

# Limpiar script temporal
rm -f /tmp/restart_ssh_safe.sh

# ─── Información final ─────────────────────────────────────────
step "Información final de SSH"

echo
info "=== CONFIGURACIÓN SSH COMPLETADA ==="
echo "👤 Usuario SSH: $USERNAME"
echo "🏠 Directorio SSH: $SSH_DIR"
echo "🔐 Claves autorizadas: $(wc -l < "$AUTHORIZED_KEYS" 2>/dev/null || echo "0")"
echo "🚪 Puerto SSH: $(grep -E '^Port|^#Port' /etc/ssh/sshd_config | tail -1 | awk '{print $2}' || echo "22")"
echo "🔒 Autenticación por contraseña: DESHABILITADA"
echo "🔒 Login root: DESHABILITADO"
echo

# Mostrar comando de conexión
SERVER_IP=$(hostname -I | awk '{print $1}')
if [[ -n "$SERVER_IP" ]]; then
    info "Comando de prueba de conexión:"
    echo "ssh -i /ruta/a/tu/clave_privada $USERNAME@$SERVER_IP"
fi

warn "IMPORTANTE: Prueba la conexión SSH desde otra terminal antes de cerrar esta sesión"
ok "Configuración SSH completada"