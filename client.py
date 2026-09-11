import socket
import os
import sys
import ssl

PORT = 9000
CLIENT_DIR = 'client_files'

if not os.path.exists(CLIENT_DIR):
    os.makedirs(CLIENT_DIR)

def show_menu():
    print("\n--- Cliente FTP Seguro ---")
    print("Comandos disponibles:")
    print(" - put <nombre_del_archivo>.<ext>")
    print(" - get <nombre_del_archivo>.<ext>")
    print(" - list (para ver los archivos en el servidor)")
    print(" - exit (para salir)")
    print("-------------------\n")

def main():
    if len(sys.argv) > 1:
        host_input = sys.argv[1]
    else:
        host_input = input("Ingresa la IP del servidor (presiona Enter para localhost): ")
        if not host_input:
            host_input = '127.0.0.1'

    if ':' in host_input:
        host, port_str = host_input.split(':')
        port = int(port_str)
    else:
        host = host_input
        port = PORT

    raw_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Configurar TLS para el cliente
    context = ssl.create_default_context()
    # Como usamos un certificado autofirmado, desactivamos la verificación de hostname y cert
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Conexión cifrada
        client = context.wrap_socket(raw_client, server_hostname=host)
        client.connect((host, port))
        print(f"Conectado al servidor TLS en {host}:{port}")
    except Exception as e:
        print(f"No se pudo conectar al servidor de forma segura: {e}")
        return

    # --- FASE DE AUTENTICACIÓN ---
    print("\n--- Autenticación Requerida ---")
    user = input("Usuario: ")
    import getpass
    password = getpass.getpass("Contraseña: ")
    
    auth_cmd = f"AUTH_CMD|{user}|{password}"
    try:
        client.send(auth_cmd.encode('utf-8'))
        auth_resp = client.recv(1024).decode('utf-8')
        if auth_resp.startswith("OK"):
            print("Autenticación exitosa.")
        else:
            print(f"Error de autenticación: {auth_resp.split('|')[-1]}")
            client.close()
            return
    except Exception as e:
        print(f"Error durante autenticación: {e}")
        client.close()
        return

    show_menu()
    
    while True:
        try:
            command_input = input("ftp> ").strip()
            if not command_input:
                continue
                
            parts = command_input.split(' ')
            cmd = parts[0].lower()
            
            if cmd == 'exit':
                break
                
            elif cmd == 'put':
                if len(parts) < 2:
                    print("Uso: put <nombre_del_archivo>.<ext>")
                    continue
                filename = parts[1]
                filepath = os.path.join(CLIENT_DIR, filename)
                
                if not os.path.exists(filepath):
                    print(f"Error: El archivo {filename} no existe en la carpeta {CLIENT_DIR}")
                    continue
                    
                filesize = os.path.getsize(filepath)
                header = f"PUT_CMD|{filename}|{filesize}"
                client.send(header.encode('utf-8'))
                
                response = client.recv(1024).decode('utf-8')
                if response == 'OK':
                    print(f"Subiendo {filename} ({filesize} bytes)...")
                    with open(filepath, 'rb') as f:
                        while True:
                            chunk = f.read(4096)
                            if not chunk:
                                break
                            client.sendall(chunk)
                    print("Archivo subido con éxito.")
                else:
                    print(f"Error al iniciar subida: {response}")
                    
            elif cmd == 'get':
                if len(parts) < 2:
                    print("Uso: get <nombre_del_archivo>.<ext>")
                    continue
                filename = parts[1]
                header = f"GET_CMD|{filename}"
                client.send(header.encode('utf-8'))
                
                response = client.recv(1024).decode('utf-8')
                resp_parts = response.split('|')
                if resp_parts[0] == 'OK':
                    filesize = int(resp_parts[1])
                    print(f"Descargando {filename} ({filesize} bytes)...")
                    client.send("READY".encode('utf-8'))
                    
                    filepath = os.path.join(CLIENT_DIR, filename)
                    with open(filepath, 'wb') as f:
                        bytes_received = 0
                        while bytes_received < filesize:
                            chunk = client.recv(min(4096, filesize - bytes_received))
                            if not chunk:
                                break
                            f.write(chunk)
                            bytes_received += len(chunk)
                    print("Archivo descargado con éxito.")
                elif resp_parts[0] == 'ERROR':
                    print(f"Error del servidor: {resp_parts[1]}")
                    
            elif cmd == 'list':
                client.send("LIST_CMD".encode('utf-8'))
                response = client.recv(1024).decode('utf-8')
                resp_parts = response.split('|')
                if resp_parts[0] == 'OK':
                    filesize = int(resp_parts[1])
                    client.send("READY".encode('utf-8'))
                    
                    bytes_received = 0
                    data = b""
                    while bytes_received < filesize:
                        chunk = client.recv(min(4096, filesize - bytes_received))
                        if not chunk:
                            break
                        data += chunk
                        bytes_received += len(chunk)
                    print("\nArchivos en el servidor:")
                    print(data.decode('utf-8'))
                    print()
            else:
                print("Comando desconocido.")
                show_menu()
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            break

    client.close()
    print("Desconectado.")

if __name__ == "__main__":
    main()
