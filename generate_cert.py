import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

def generate_self_signed_cert():
    print("Generando clave privada RSA...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Write private key
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    print("Generando certificado auto-firmado...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Bogota"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bogota"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Servidor FTP Seguro"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 365 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Write certificate
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    print("Certificados generados exitosamente: cert.pem y key.pem")

if __name__ == "__main__":
    try:
        generate_self_signed_cert()
    except ImportError:
        print("Error: Necesitas instalar la librería 'cryptography'.")
        print("Ejecuta: pip install cryptography")
        import sys
        sys.exit(1)
