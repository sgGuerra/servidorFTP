# Servidor FTP Seguro 🛡️

Un servidor de transferencia de archivos implementado en Python puro sobre sockets TCP, diseñado con un enfoque fuerte en la ciberseguridad.

Este proyecto comenzó como un servidor de transferencia simple (`PUT`, `GET`, `LIST`) y evolucionó para incluir protección de grado empresarial contra ataques comunes.

## 🚀 Características de Seguridad Implementadas

1. **Cifrado TLS (Transport Layer Security)**
   Todo el tráfico entre el cliente y el servidor viaja de manera cifrada utilizando la librería `ssl` nativa de Python, previniendo ataques de interceptación (Man-In-The-Middle).
2. **Autenticación de Acceso**
   El servidor implementa un sistema de validación (estado `AUTH_CMD`). Cualquier intento de listar o transferir archivos sin haberse autenticado primero es rechazado inmediatamente.
3. **Rate Limiting**
   Prevención de ataques de fuerza bruta y escaneo. El servidor rastrea las direcciones IP y bloquea cualquier intento de conexión con una frecuencia menor a 1 segundo.
4. **Prevención de Fuzzing y Path Traversal**
   - **Path Traversal Bloqueado**: Sanitización estricta de los nombres de archivo recibidos. Se prohíbe el uso de directorios relativos (`../`) y caracteres especiales.
   - **Fuzzing y DoS**: Límite de tamaño de archivo (máximo 100 MB) y límites de longitud de nombres de archivo para prevenir la caída del servidor y llenado de disco no autorizado.

---

## 💻 Instrucciones de Uso

### 1. Requisitos Previos
Necesitarás Python 3.x y la librería `cryptography` para generar los certificados.
```bash
pip install cryptography
```

### 2. Generación de Certificados TLS
Antes de iniciar el servidor, genera tus llaves locales autofirmadas (¡este paso es obligatorio y crea los archivos `cert.pem` y `key.pem` que están protegidos en el `.gitignore`!):
```bash
python generate_cert.py
```

### 3. Iniciar el Servidor
En una consola, levanta el servidor:
```bash
python server.py
```
> El servidor quedará a la escucha en `0.0.0.0:9000`.

### 4. Conectar el Cliente
En otra consola (o en otra computadora de la red), inicia el cliente y sigue las instrucciones en pantalla:
```bash
python client.py
```

