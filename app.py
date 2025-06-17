from flask import Flask, jsonify, request
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
from librouteros import connect
import logging

# Configurar logging para depuración
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Habilita CORS para todas las rutas

# Configuración
MIKROTIK_HOST = 'http://192.168.88.1'  # Para API REST
MIKROTIK_API_HOST = '192.168.88.1'     # Para API nativa (sin http://)
USERNAME = 'admin'
PASSWORD = 'susan2610'
API_PORT = 8728  # Puerto API nativa (no HTTP)

def get_api():
    """Establece conexión con la API nativa de RouterOS"""
    try:
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT
        )
        logger.debug("Conexión establecida con RouterOS")
        return connection
    except Exception as e:
        logger.error(f"Error al conectar con RouterOS: {str(e)}")
        raise

# Función para obtener las leases DHCP
@app.route('/users', methods=['GET'])
def get_dhcp_leases():
    url = f"{MIKROTIK_HOST}/rest/ip/dhcp-server/lease"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        response.raise_for_status()
        leases = response.json()
        return jsonify(leases)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

# Función mejorada para bloquear un dispositivo por MAC usando API nativa
@app.route('/devices/bloquear', methods=['POST'])
def block_device():
    data = request.get_json()
    mac_address = data.get('mac_address')
    if not mac_address:
        return jsonify({'error': 'Se requiere la dirección MAC'}), 400

    # Normalizar MAC a mayúsculas para RouterOS
    mac_address = mac_address.upper()
    comment = data.get('comment', 'Bloqueado por API')

    try:
        api = get_api()
        logger.debug(f"Intentando bloquear MAC: {mac_address}")
        
        # Verificar si ya existe una regla para esta MAC
        existing_rules = api.path('ip', 'firewall', 'filter')
        for rule in existing_rules:
            if rule.get('src-mac-address') == mac_address and rule.get('action') == 'drop':
                return jsonify({'message': f'El dispositivo {mac_address} ya está bloqueado'}), 200
        
        # Crear regla de bloqueo en cadena forward (tráfico a internet)
        logger.debug("Agregando regla en cadena forward")
        api.path('ip', 'firewall', 'filter').add(
            chain='forward',
            **{'src-mac-address': mac_address},
            action='drop',
            comment=comment
        )
        
        # Intentar agregar regla para bloquear ping (ICMP)
        try:
            logger.debug("Intentando agregar regla para bloquear ICMP")
            api.path('ip', 'firewall', 'filter').add(
                chain='input',
                **{'src-mac-address': mac_address},
                protocol='icmp',
                action='drop',
                comment=f"{comment} (ping)"
            )
            return jsonify({'message': f'Dispositivo {mac_address} bloqueado completamente (tráfico y ping)'})
        except Exception as e:
            logger.warning(f"No se pudo crear regla ICMP: {str(e)}")
            return jsonify({'message': f'Dispositivo {mac_address} bloqueado (solo tráfico saliente)'})
            
    except Exception as e:
        logger.error(f"Error al bloquear MAC {mac_address}: {str(e)}")
        return jsonify({'error': f'Error al comunicarse con RouterOS: {str(e)}'}), 500

# Función para desbloquear un dispositivo por MAC usando API nativa
@app.route('/devices/desbloquear', methods=['POST'])
def unblock_device():
    data = request.get_json()
    mac_address = data.get('mac_address')
    if not mac_address:
        return jsonify({'error': 'Se requiere la dirección MAC'}), 400

    # Normalizar MAC a mayúsculas
    mac_address = mac_address.upper()

    try:
        api = get_api()
        logger.debug(f"Intentando desbloquear MAC: {mac_address}")
        eliminadas = 0
        
        # Encontrar y eliminar todas las reglas para esta MAC
        for rule in api.path('ip', 'firewall', 'filter'):
            if rule.get('src-mac-address') == mac_address and rule.get('action') == 'drop':
                logger.debug(f"Eliminando regla: {rule['.id']}")
                api.path('ip', 'firewall', 'filter').remove(rule['.id'])
                eliminadas += 1
        
        if eliminadas > 0:
            return jsonify({'message': f'Dispositivo {mac_address} desbloqueado. Se eliminaron {eliminadas} reglas'})
        else:
            return jsonify({'message': f'No se encontraron reglas de bloqueo para {mac_address}'}), 404
    except Exception as e:
        logger.error(f"Error al desbloquear MAC {mac_address}: {str(e)}")
        return jsonify({'error': f'Error al comunicarse con RouterOS: {str(e)}'}), 500

@app.route('/devices/staticIP', methods=['POST'])
def assign_static_ip_native():
    data = request.get_json()
    mac_address = data.get('mac_address')
    ip_address = data.get('ip_address')
    comment = data.get('comment', 'Asignación estática por API nativa')

    if not mac_address or not ip_address:
        return jsonify({'error': 'Se requieren la dirección MAC y la IP'}), 400

    mac_address = mac_address.upper()

    try:
        api = get_api()

        # Eliminar lease previa si existe
        for lease in api.path('ip', 'dhcp-server', 'lease'):
            if lease.get('mac-address') == mac_address:
                logger.debug(f"Eliminando lease existente para {mac_address}")
                api.path('ip', 'dhcp-server', 'lease').remove(lease['.id'])

        # Crear lease nueva
        logger.debug(f"Agregando nueva lease para {mac_address} con IP {ip_address}")
        response = api.path('ip', 'dhcp-server', 'lease').add(
            **{
                'mac-address': mac_address,
                'address': ip_address,
                'comment': comment
            }
        )
        
        # Encontrar la lease recién creada
        lease_id = None
        for lease in api.path('ip', 'dhcp-server', 'lease'):
            if lease.get('mac-address') == mac_address and lease.get('address') == ip_address:
                lease_id = lease['.id']
                break
                
        if not lease_id:
            return jsonify({'message': f'IP {ip_address} asignada a {mac_address}, pero no se pudo encontrar para hacerla estática'}), 207
        
        # Usar REST API para hacer la lease estática
        logger.debug(f"Haciendo estática la lease {lease_id} usando REST API")
        url = f"{MIKROTIK_HOST}/rest/ip/dhcp-server/lease/{lease_id}/make-static"
        response = requests.post(
            url, 
            auth=HTTPBasicAuth(USERNAME, PASSWORD)
        )
        
        if response.status_code in [200, 201, 204]:
            return jsonify({'message': f'IP {ip_address} asignada estáticamente a {mac_address}'})
        else:
            logger.warning(f"Error al hacer estática: {response.status_code} - {response.text}")
            return jsonify({'message': f'IP {ip_address} asignada a {mac_address}, pero podría no ser estática'}), 207

    except Exception as e:
        logger.error(f"Error al asignar IP estática con API nativa: {str(e)}")
        return jsonify({'error': f'Error al comunicarse con RouterOS: {str(e)}'}), 500

# Función para obtener el historial de conexiones por MAC
@app.route('/logs/<mac>', methods=['GET'])
def get_logs(mac):
    url = f"{MIKROTIK_HOST}/rest/log"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        response.raise_for_status()
        logs = response.json()
        filtered_logs = [log for log in logs if mac.upper() in log.get('message', '')]
        return jsonify(filtered_logs)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

# Función para bloquear un dispositivo por dirección IP
@app.route('/devices/bloquear-ip', methods=['POST'])
def block_ip_device():
    data = request.get_json()
    ip_address = data.get('ip_address')
    if not ip_address:
        return jsonify({'error': 'Se requiere la dirección IP'}), 400

    # La ruta correcta para RouterOS 7.10.1
    api_url = f"{MIKROTIK_HOST}/rest/ip/firewall/nat/add"
    
    # Probar con POST a /rest/ip/firewall/filter/add para RouterOS 7.x
    rule = {
        "chain": "forward",
        "src-address": ip_address,
        "action": "drop"
    }

    try:
        # Intentar con el endpoint correcto para RouterOS 7.x
        print(f"Intentando con endpoint: /rest/ip/firewall/filter/add")
        response = requests.put(
            f"{MIKROTIK_HOST}/rest/ip/firewall/filter/add", 
            json=rule, 
            auth=HTTPBasicAuth(USERNAME, PASSWORD)
        )
        print(f"Respuesta: {response.status_code} - {response.text}")
        
        if response.status_code == 201 or response.status_code == 200:
            return jsonify({'message': f'IP {ip_address} bloqueada exitosamente'})
        
        # Si falla, intentar con la estructura antigua
        print(f"Intentando con endpoint alternativo...")
        rule2 = {
            "chain": "forward",
            "src-address": ip_address,
            "action": "drop"
        }
        alt_response = requests.post(
            f"{MIKROTIK_HOST}/rest/ip/firewall/filter", 
            json=rule2, 
            auth=HTTPBasicAuth(USERNAME, PASSWORD)
        )
        print(f"Respuesta alternativa: {alt_response.status_code} - {alt_response.text}")
        
        if alt_response.status_code == 201 or alt_response.status_code == 200:
            return jsonify({'message': f'IP {ip_address} bloqueada exitosamente (usando endpoint alternativo)'})
        
        # Intentar con comando directo a través de REST API
        print("Intentando con comando directo...")
        command = {
            "cmd": "/ip firewall filter add chain=forward src-address=" + ip_address + " action=drop comment=\"Bloqueado por API\""
        }
        cmd_response = requests.post(
            f"{MIKROTIK_HOST}/rest/execute", 
            json=command, 
            auth=HTTPBasicAuth(USERNAME, PASSWORD)
        )
        print(f"Respuesta comando: {cmd_response.status_code} - {cmd_response.text}")
        
        if cmd_response.status_code == 200:
            return jsonify({'message': f'IP {ip_address} bloqueada mediante ejecución de comando'})
        
        return jsonify({
            'error': 'No se pudo crear regla de firewall',
            'detalles': [
                f"Intento 1: {response.status_code} - {response.text}",
                f"Intento 2: {alt_response.status_code} - {alt_response.text}",
                f"Intento 3: {cmd_response.status_code} - {cmd_response.text}"
            ]
        }), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/devices/status/<mac_address>', methods=['GET'])
def check_device_status(mac_address):
    # Normalizar MAC address
    mac_address = mac_address.upper()
    
    # Verificar si hay reglas de firewall que bloqueen este dispositivo
    url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        response.raise_for_status()
        rules = response.json()
        
        # Buscar reglas que bloqueen esta MAC
        for rule in rules:
            if rule.get('src-mac-address') == mac_address and rule.get('action') == 'drop':
                return jsonify({'blocked': True})
                
        return jsonify({'blocked': False})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e), 'blocked': False}), 500
# Función para desbloquear un dispositivo por dirección IP
@app.route('/devices/desbloquear-ip', methods=['POST'])
def unblock_ip_device():
    data = request.get_json()
    ip_address = data.get('ip_address')
    if not ip_address:
        return jsonify({'error': 'Se requiere la dirección IP'}), 400

    # Obtener las reglas de firewall existentes
    url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        response.raise_for_status()
        rules = response.json()
        # Buscar y eliminar las reglas que coincidan con la IP
        eliminadas = 0
        for rule in rules:
            if ((rule.get('src-address') == ip_address or rule.get('dst-address') == ip_address) 
                and rule.get('action') == 'drop'):
                rule_id = rule.get('.id')
                delete_url = f"{url}/{rule_id}"
                del_response = requests.delete(delete_url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
                del_response.raise_for_status()
                eliminadas += 1
        
        if eliminadas > 0:
            return jsonify({'message': f'IP {ip_address} desbloqueada exitosamente. Se eliminaron {eliminadas} reglas.'})
        else:
            return jsonify({'message': f'No se encontraron reglas de bloqueo para la IP {ip_address}'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Puedes validar contra variables de entorno, base de datos o directamente:
    if username == USERNAME and password == PASSWORD:
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "message": "Credenciales incorrectas"}), 401


if __name__ == '__main__':
    app.run(debug=True)
