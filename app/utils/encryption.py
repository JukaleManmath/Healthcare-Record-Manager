import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import structlog

logger = structlog.get_logger()

class EncryptionManager:
    """Manager for data encryption and decryption"""
    
    def __init__(self, key=None):
        """Initialize encryption manager with key"""
        if key is None:
            key = os.environ.get('ENCRYPTION_KEY')
        
        if not key:
            raise ValueError("Encryption key is required")
        
        # Generate Fernet key from the provided key
        salt = b'healthcare_salt_2025'  # In production, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_bytes = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        self.fernet = Fernet(key_bytes)
    
    def encrypt(self, data):
        """Encrypt data"""
        if not data:
            return None
        
        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = str(data).encode('utf-8')
            
            encrypted_data = self.fernet.encrypt(data_bytes)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        if not encrypted_data:
            return None
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise

# Global encryption manager instance
_encryption_manager = None

def get_encryption_manager():
    """Get or create encryption manager instance"""
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager

def encrypt_data(data):
    """Encrypt data using the global encryption manager"""
    manager = get_encryption_manager()
    return manager.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt data using the global encryption manager"""
    manager = get_encryption_manager()
    return manager.decrypt(encrypted_data)

def generate_encryption_key():
    """Generate a new encryption key"""
    return Fernet.generate_key().decode('utf-8')

def hash_sensitive_data(data):
    """Hash sensitive data for verification purposes"""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()

def mask_ssn(ssn):
    """Mask SSN for display (e.g., ***-**-1234)"""
    if not ssn or len(ssn) < 4:
        return ssn
    return '*' * (len(ssn) - 4) + ssn[-4:]

def mask_phone(phone):
    """Mask phone number for display (e.g., (***) ***-1234)"""
    if not phone or len(phone) < 4:
        return phone
    return '*' * (len(phone) - 4) + phone[-4:]

def mask_email(email):
    """Mask email for display (e.g., j***@example.com)"""
    if not email or '@' not in email:
        return email
    
    username, domain = email.split('@', 1)
    if len(username) <= 1:
        return email
    
    masked_username = username[0] + '*' * (len(username) - 1)
    return f"{masked_username}@{domain}"
