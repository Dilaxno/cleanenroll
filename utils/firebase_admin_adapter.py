"""
Firebase Admin adapter module that provides a dummy Firestore implementation.
This allows for a smooth transition from Firestore to PostgreSQL while keeping Firebase Authentication.
"""
import logging
from typing import Any, Dict, List, Optional, Callable, Union
import firebase_admin
from firebase_admin import auth

logger = logging.getLogger(__name__)

# Initialize Firebase Admin if not already initialized
try:
    default_app = firebase_admin.get_app()
except ValueError:
    # Use application default credentials
    default_app = firebase_admin.initialize_app()

# Export Firebase Admin auth for authentication
admin_auth = auth

# Dummy Firestore implementation for Firebase Admin
class DummyAdminFirestore:
    def __init__(self):
        logger.warning("Using dummy Firebase Admin Firestore implementation. All operations will be no-ops.")
    
    def client(self):
        return self
    
    def collection(self, name: str):
        logger.warning(f"Accessing removed Firestore collection: {name}")
        return DummyAdminCollection(name)
    
    def document(self, path: str):
        logger.warning(f"Accessing removed Firestore document: {path}")
        return DummyAdminDocument(path)
        
    def batch(self):
        return DummyAdminBatch()
        
    def transaction(self):
        return DummyAdminTransaction()

class DummyAdminCollection:
    def __init__(self, name: str):
        self.name = name
    
    def document(self, doc_id: str = None):
        return DummyAdminDocument(f"{self.name}/{doc_id}" if doc_id else self.name)
    
    def where(self, field: str, op: str, value: Any):
        return DummyAdminQuery(self.name)
    
    def get(self):
        return []
    
    def stream(self):
        return []
    
    def add(self, document_data: Dict[str, Any], document_id: Optional[str] = None):
        logger.warning(f"Attempted write to removed Firestore collection: {self.name}")
        return None
        
    def list_documents(self):
        return []

class DummyAdminDocument:
    def __init__(self, path: str):
        self.path = path
        self.id = path.split('/')[-1] if '/' in path else path
    
    def get(self):
        return DummyAdminDocumentSnapshot(self.path, exists=False)
    
    def set(self, document_data: Dict[str, Any], merge: bool = False):
        logger.warning(f"Attempted write to removed Firestore document: {self.path}")
        return None
    
    def update(self, field_updates: Dict[str, Any]):
        logger.warning(f"Attempted update to removed Firestore document: {self.path}")
        return None
    
    def delete(self):
        logger.warning(f"Attempted delete of removed Firestore document: {self.path}")
        return None
    
    def collection(self, name: str):
        return DummyAdminCollection(f"{self.path}/{name}")
        
    def collections(self):
        return []

class DummyAdminDocumentSnapshot:
    def __init__(self, path: str, exists: bool = False):
        self.path = path
        self.id = path.split('/')[-1] if '/' in path else path
        self._exists = exists
        self._data = {}
        self.reference = DummyAdminDocument(path)
    
    def exists(self):
        return self._exists
    
    def to_dict(self):
        return self._data
    
    def get(self, field_path: str):
        return None

class DummyAdminQuery:
    def __init__(self, collection_name: str):
        self.collection_name = collection_name
    
    def where(self, field: str, op: str, value: Any):
        return self
    
    def order_by(self, field: str, direction: Optional[str] = None):
        return self
    
    def limit(self, count: int):
        return self
    
    def get(self):
        return []
    
    def stream(self):
        return []
        
    def offset(self, count: int):
        return self

class DummyAdminBatch:
    def __init__(self):
        pass
    
    def set(self, ref, data, merge=False):
        return self
    
    def update(self, ref, data):
        return self
    
    def delete(self, ref):
        return self
    
    def commit(self):
        return []

class DummyAdminTransaction:
    def __init__(self):
        pass
    
    def set(self, ref, data, merge=False):
        return self
    
    def update(self, ref, data):
        return self
    
    def delete(self, ref):
        return self
    
    def get(self, ref):
        return DummyAdminDocumentSnapshot(str(ref), exists=False)

# Create a singleton instance
admin_firestore = DummyAdminFirestore()

# Export for compatibility with existing imports
firestore = admin_firestore