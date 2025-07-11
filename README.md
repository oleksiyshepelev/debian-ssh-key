# Configuración segura de SSH en Debian

Este directorio contiene el script `configure-ssh.sh`, el cual automatiza la configuración segura del servicio SSH para un usuario no root en sistemas Debian y derivados.

## ¿Qué hace el script?

- Solicita el nombre de usuario para el que se configurará el acceso SSH (no permite root).
- Crea y asegura el directorio `.ssh` y el archivo `authorized_keys` para el usuario.
- Permite añadir una clave pública SSH de forma interactiva o desde archivo.
- Aplica una configuración segura al daemon SSH (`sshd_config`):
  - Deshabilita autenticación por contraseña y acceso root.
  - Habilita solo autenticación por clave pública.
  - Limita reintentos y endurece parámetros de seguridad.
  - Añade opciones adicionales como deshabilitar X11Forwarding, AgentForwarding, TCPForwarding, etc.
- Realiza backup del archivo original de configuración de SSH.
- Valida la configuración antes de reiniciar el servicio.
- Reinicia SSH de forma segura y verifica que el servicio siga activo.
- Muestra información final y un comando de conexión sugerido.

## Requisitos

- Debian 11/12 o derivado (Ubuntu, etc.)
- Acceso root (el script debe ejecutarse como root)
- El usuario para el que se configura SSH debe existir previamente

## Uso

1. Da permisos de ejecución al script:

   ```bash
   chmod +x configure-ssh.sh
   ```

2. Ejecútalo como root:

   ```bash
   sudo ./configure-ssh.sh
   ```

3. Sigue las instrucciones interactivas para añadir la clave pública SSH.

## Notas

- El script NO permite configurar SSH para el usuario root por seguridad.
- Realiza un backup de `/etc/ssh/sshd_config` antes de modificarlo.
- Si el servicio SSH no puede reiniciarse correctamente, restaura la configuración anterior automáticamente.
- Antes de cerrar tu sesión, prueba la nueva conexión SSH desde otra terminal.

## Verificación

Al finalizar, el script mostrará:

- Usuario configurado
- Ruta del directorio `.ssh`
- Número de claves autorizadas
- Puerto SSH configurado
- Comando sugerido para conectar

## Autor

- Basado en buenas prácticas de seguridad para servidores Debian.
