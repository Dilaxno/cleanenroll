"""
Firebase adapter module that provides a dummy Firestore implementation.
This allows for a smooth transition from Firestore to PostgreSQL.
"""
import logging
from typing import Any, Dict, List, Optional, Callable, Union

logger = logging.getLogger(__name__)

class DummyFirestoreCollection:
    def __init__(self, name: str):
        self.name = name
        logger.warning(f"Accessing removed Firestore collection: {name}")
    
    def document(self, doc_id: str):
        return DummyFirestoreDocument(f"{self.name}/{doc_id}")
    
    def where(self, field: str, op: str, value: Any):
        return DummyFirestoreQuery(self.name)
    
    def get(self):
        return []
    
    def stream(self):
        return []
    
    def add(self, data: Dict[str, Any], document_id: Optional[str] = None):
        logger.warning(f"Attempted write to removed Firestore collection: {self.name}")
        return None

class DummyFirestoreDocument:
    def __init__(self, path: str):
        self.path = path
        logger.warning(f"Accessing removed Firestore document: {path}")
    
    def get(self):
        return DummyDocumentSnapshot(self.path, exists=False)
    
    def set(self, data: Dict[str, Any], merge: bool = False):
        logger.warning(f"Attempted write to removed Firestore document: {self.path}")
        return None
    
    def update(self, data: Dict[str, Any]):
        logger.warning(f"Attempted update to removed Firestore document: {self.path}")
        return None
    
    def delete(self):
        logger.warning(f"Attempted delete of removed Firestore document: {self.path}")
        return None
    
    def collection(self, name: str):
        return DummyFirestoreCollection(f"{self.path}/{name}")

class DummyDocumentSnapshot:
    def __init__(self, path: str, exists: bool = False):
        self.path = path
        self._exists = exists
        self._data = {}
    
    def exists(self):
        return self._exists
    
    def to_dict(self):
        return self._data
    
    def get(self, field: str):
        return None

class DummyFirestoreQuery:
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

class DummyFirestore:
    def __init__(self):
        logger.warning("Using dummy Firestore implementation. All operations will be no-ops.")
    
    def collection(self, name: str):
        return DummyFirestoreCollection(name)
    
    def document(self, path: str):
        return DummyFirestoreDocument(path)
    
    def batch(self):
        return DummyFirestoreBatch()
    
    def transaction(self):
        return DummyFirestoreTransaction()

class DummyFirestoreBatch:
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

class DummyFirestoreTransaction:
    def __init__(self):
        pass
    
    def set(self, ref, data, merge=False):
        return self
    
    def update(self, ref, data):
        return self
    
    def delete(self, ref):
        return self
    
    def get(self, ref):
        return DummyDocumentSnapshot(str(ref), exists=False)

# Create a singleton instance
firestore_client = DummyFirestore()

def get_firestore_client():
    """
    Returns a dummy Firestore client that logs warnings and returns empty results.
    This is used to maintain backward compatibility while transitioning to PostgreSQL.
    """
    return firestore_client