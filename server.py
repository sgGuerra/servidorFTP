import socket
import threading
import os
import ssl
import time
import re

HOST = '0.0.0.0'
PORT = 9000
SERVER_DIR = 'server_files'
MAX_FILE_SIZE = 100 * 1024 * 1024 # 100 MB
MAX_FILENAME_LEN = 255
AUTH_USER = "admin"
AUTH_PASS = "secreto123"

# Diccionario para Rate Limiting (IP: último timestamp)
ip_tracker = {}
RATE_LIMIT_DELAY = 1.0 # 1 segundo entre conexiones

if not os.path.exists(SERVER_DIR):
    os.makedirs(SERVER_DIR)

def is_safe_filename(filename):
    # Fuzzing y Traversal protection: Solo permite alfanuméricos, puntos, guiones y guiones bajos. Sin rutas extrañas.
    if len(filename) > MAX_FILENAME_LEN or len(filename) == 0:
        return False
    if not re.match(r'^[\w\-. ]+$', filename):
        return False
    if ".." in filename:
        return False
    return True

def handle_client(conn, addr):
    ip = addr[0]
    
    # --- RATE LIMITING ---
    current_time = time.time()
    last_time = ip_tracker.get(ip, 0)
    if current_time - last_time < RATE_LIMIT_DELAY:
        print(f"[RATE LIMIT] Bloqueando conexión rápida desde {ip}")
        conn.close()
        return
    ip_tracker[ip] = current_time

    print(f"[NUEVA CONEXION] {addr} conectado mediante TLS.")
    is_authenticated = False
    
    try:
        while True:
            try:
                # Recibir comando (hasta 1024 bytes de encabezado)
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break
                
                parts = data.split('|')
                cmd = parts[0]
                
                # --- PROTECCIÓN DE SEGURIDAD ---
                if cmd not in ['AUTH_CMD', 'PUT_CMD', 'GET_CMD', 'LIST_CMD']:
                    print(f"[ALERTA] Comando no autorizado detectado desde {addr}: {cmd}. Desconectando.")
                    break
                    
                # --- AUTENTICACIÓN ---
                if cmd == 'AUTH_CMD':
                    if len(parts) < 3:
                        conn.send("ERROR|Formato de auth inválido".encode('utf-8'))
                        break
                    user = parts[1]
                    password = parts[2]
                    if user == AUTH_USER and password == AUTH_PASS:
                        is_authenticated = True
                        conn.send("OK|Autenticado correctamente".encode('utf-8'))
                    else:
                        conn.send("ERROR|Credenciales incorrectas".encode('utf-8'))
                        break # Desconectar al fallar
                    continue
                
                if not is_authenticated:
                    conn.send("ERROR|Debe autenticarse primero".encode('utf-8'))
                    break
                
                if cmd == 'PUT_CMD':
                    if len(parts) < 3:
                        break
                    
                    # Prevención Traversal y Fuzzing de nombres
                    filename = os.path.basename(parts[1])
                    if not is_safe_filename(filename):
                        conn.send("ERROR|Nombre de archivo inválido o peligroso".encode('utf-8'))
                        continue
                        
                    try:
                        filesize = int(parts[2])
                    except ValueError:
                        break
                        
                    # Prevención Fuzzing de tamaño de archivo (DoS por llenado de disco)
                    if filesize > MAX_FILE_SIZE or filesize < 0:
                        conn.send("ERROR|Tamaño de archivo excede el límite permitido".encode('utf-8'))
                        continue
                        
                    conn.send("OK".encode('utf-8'))
                    
                    filepath = os.path.join(SERVER_DIR, filename)
                    with open(filepath, 'wb') as f:
                        bytes_received = 0
                        while bytes_received < filesize:
                            chunk = conn.recv(min(4096, filesize - bytes_received))
                            if not chunk:
                                break
                            f.write(chunk)
                            bytes_received += len(chunk)
                    print(f"[RECEPCION] Archivo {filename} recibido de {addr}")
                    
                elif cmd == 'GET_CMD':
                    if len(parts) < 2:
                        break
                    filename = os.path.basename(parts[1])
                    if not is_safe_filename(filename):
                        conn.send("ERROR|Nombre de archivo inválido".encode('utf-8'))
                        continue
                        
                    filepath = os.path.join(SERVER_DIR, filename)
                    
                    if os.path.exists(filepath):
                        filesize = os.path.getsize(filepath)
                        conn.send(f"OK|{filesize}".encode('utf-8'))
                        
                        response = conn.recv(1024).decode('utf-8')
                        if response == 'READY':
                            with open(filepath, 'rb') as f:
                                while True:
                                    chunk = f.read(4096)
                                    if not chunk:
                                        break
                                    conn.sendall(chunk)
                            print(f"[ENVIO] Archivo {filename} enviado a {addr}")
                    else:
                        conn.send("ERROR|Archivo no encontrado".encode('utf-8'))
                        
                elif cmd == 'LIST_CMD':
                    files = os.listdir(SERVER_DIR)
                    files_str = "\n".join(files) if files else "El servidor no tiene archivos."
                    files_bytes = files_str.encode('utf-8')
                    conn.send(f"OK|{len(files_bytes)}".encode('utf-8'))
                    response = conn.recv(1024).decode('utf-8')
                    if response == 'READY':
                        conn.sendall(files_bytes)

            except Exception as e:
                print(f"[ERROR COMANDO] {addr}: {e}")
                try:
                    conn.send("ERROR|Excepcion procesando comando".encode('utf-8'))
                except:
                    pass
                break # Rompemos el ciclo para este cliente si hay un error crítico

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[DESCONEXION] {addr} desconectado.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    # Configurar TLS
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    except Exception as e:
        print(f"[ERROR TLS] No se pudieron cargar los certificados TLS: {e}")
        return
        
    print(f"[INICIO] Servidor TLS escuchando en {HOST}:{PORT}")
    
    try:
        while True:
            raw_conn, addr = server.accept()
            try:
                # Envolver la conexión en TLS
                conn = context.wrap_socket(raw_conn, server_side=True)
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()
                print(f"[CONEXIONES ACTIVAS] {threading.active_count() - 1}")
            except ssl.SSLError as e:
                print(f"[ERROR TLS] Conexión rechazada o fallo handshake desde {addr}: {e}")
                raw_conn.close()
    except KeyboardInterrupt:
        print("\n[APAGADO] Servidor detenido manualmente (Ctrl+C).")
    except Exception as e:
        print(f"\n[ERROR CRITICO] Fallo en el servidor principal: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
