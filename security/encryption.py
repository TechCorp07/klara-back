"""
Security enhancements for Klararety platform.
Implements AES-256 encryption, TLS 1.3 configuration, and vulnerability scanning integration.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.conf import settings
import logging

logger = logging.getLogger('security')

class AES256Encryption:
    """
    AES-256 encryption utility for sensitive data.
    Implements encryption and decryption using AES-256 in CBC mode with PKCS7 padding.
    """
    
    @staticmethod
    def generate_key():
        """
        Generate a random AES-256 key.
        """
        return os.urandom(32)  # 32 bytes = 256 bits
    
    @staticmethod
    def generate_iv():
        """
        Generate a random initialization vector.
        """
        return os.urandom(16)  # 16 bytes = 128 bits for AES
    
    @classmethod
    def encrypt(cls, plaintext, key=None):
        """
        Encrypt data using AES-256-CBC with PKCS7 padding.
        
        Args:
            plaintext (str or bytes): Data to encrypt
            key (bytes, optional): Encryption key (32 bytes). If not provided, uses settings.ENCRYPTION_KEY
            
        Returns:
            dict: Dictionary containing base64-encoded 'iv' and 'ciphertext'
        """
        if key is None:
            key = settings.ENCRYPTION_KEY
            
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate IV
        iv = cls.generate_iv()
        
        # Pad the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Return base64 encoded values
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    @classmethod
    def decrypt(cls, encrypted_data, key=None):
        """
        Decrypt data that was encrypted with AES-256-CBC and PKCS7 padding.
        
        Args:
            encrypted_data (dict): Dictionary containing base64-encoded 'iv' and 'ciphertext'
            key (bytes, optional): Decryption key (32 bytes). If not provided, uses settings.ENCRYPTION_KEY
            
        Returns:
            bytes: Decrypted data
        """
        if key is None:
            key = settings.ENCRYPTION_KEY
            
        # Decode base64 values
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    @classmethod
    def encrypt_to_string(cls, plaintext, key=None):
        """
        Encrypt data and return as a single base64-encoded string.
        
        Args:
            plaintext (str or bytes): Data to encrypt
            key (bytes, optional): Encryption key (32 bytes). If not provided, uses settings.ENCRYPTION_KEY
            
        Returns:
            str: Base64-encoded string containing IV and ciphertext
        """
        encrypted = cls.encrypt(plaintext, key)
        combined = base64.b64encode(
            base64.b64decode(encrypted['iv']) + base64.b64decode(encrypted['ciphertext'])
        ).decode('utf-8')
        return combined
    
    @classmethod
    def decrypt_from_string(cls, encoded_string, key=None):
        """
        Decrypt data from a single base64-encoded string.
        
        Args:
            encoded_string (str): Base64-encoded string containing IV and ciphertext
            key (bytes, optional): Decryption key (32 bytes). If not provided, uses settings.ENCRYPTION_KEY
            
        Returns:
            bytes: Decrypted data
        """
        combined = base64.b64decode(encoded_string)
        iv = combined[:16]  # First 16 bytes are IV
        ciphertext = combined[16:]  # Rest is ciphertext
        
        encrypted_data = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        
        return cls.decrypt(encrypted_data, key)


class VulnerabilityScanner:
    """
    Integration with vulnerability scanning tools.
    Provides methods to scan code, dependencies, and infrastructure.
    """
    
    @staticmethod
    def scan_dependencies():
        """
        Scan project dependencies for vulnerabilities using safety.
        
        Returns:
            dict: Scan results
        """
        try:
            import subprocess
            import json
            
            # Run safety check and capture output
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    'status': 'success',
                    'vulnerabilities': [],
                    'message': 'No vulnerabilities found'
                }
            else:
                # Parse JSON output
                try:
                    vulnerabilities = json.loads(result.stdout)
                    return {
                        'status': 'warning',
                        'vulnerabilities': vulnerabilities,
                        'message': f'Found {len(vulnerabilities)} vulnerabilities'
                    }
                except json.JSONDecodeError:
                    return {
                        'status': 'error',
                        'message': 'Failed to parse safety output',
                        'output': result.stdout
                    }
                    
        except Exception as e:
            logger.exception(f"Error scanning dependencies: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning dependencies: {str(e)}'
            }
    
    @staticmethod
    def scan_code():
        """
        Scan code for security issues using bandit.
        
        Returns:
            dict: Scan results
        """
        try:
            import subprocess
            import json
            
            # Run bandit scan and capture output
            result = subprocess.run(
                ['bandit', '-r', '.', '-f', 'json'],
                capture_output=True,
                text=True
            )
            
            # Parse JSON output
            try:
                scan_data = json.loads(result.stdout)
                return {
                    'status': 'success',
                    'results': scan_data,
                    'message': f"Scan completed: {scan_data.get('metrics', {}).get('_totals', {}).get('SEVERITY.HIGH', 0)} high severity issues found"
                }
            except json.JSONDecodeError:
                return {
                    'status': 'error',
                    'message': 'Failed to parse bandit output',
                    'output': result.stdout
                }
                
        except Exception as e:
            logger.exception(f"Error scanning code: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning code: {str(e)}'
            }
    
    @staticmethod
    def scan_docker_image(image_name):
        """
        Scan Docker image for vulnerabilities using trivy.
        
        Args:
            image_name (str): Name of Docker image to scan
            
        Returns:
            dict: Scan results
        """
        try:
            import subprocess
            import json
            
            # Run trivy scan and capture output
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', image_name],
                capture_output=True,
                text=True
            )
            
            # Parse JSON output
            try:
                scan_data = json.loads(result.stdout)
                return {
                    'status': 'success',
                    'results': scan_data,
                    'message': f"Scan completed for {image_name}"
                }
            except json.JSONDecodeError:
                return {
                    'status': 'error',
                    'message': 'Failed to parse trivy output',
                    'output': result.stdout
                }
                
        except Exception as e:
            logger.exception(f"Error scanning Docker image: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning Docker image: {str(e)}'
            }


# TLS 1.3 Configuration for Django
TLS_13_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
]

# NGINX TLS 1.3 Configuration
NGINX_TLS_13_CONFIG = """
# TLS 1.3 Configuration for NGINX
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_ecdh_curve secp384r1;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
"""

# Security Headers Middleware
class SecurityHeadersMiddleware:
    """
    Middleware to add security headers to HTTP responses.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        return response
