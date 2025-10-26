"""
Firebase Admin adapter module that provides a dummy Firestore implementation.
This allows for a smooth transition from Firestore to PostgreSQL while keeping Firebase Authentication.

When FIRESTORE_DISABLED is set (1/true/yes/on), this module will NOT initialize
the Firebase Admin SDK and will only expose dummy Firestore/auth objects to ensure
no external network calls are made to Google APIs.
"""
import logging
from typing import Any, Dict, List, Optional, Callable, Union
import os
try:
    import firebase_admin  # type: ignore
    from firebase_admin import auth, credentials  # type: ignore
except Exception:  # pragma: no cover
    firebase_admin = None  # type: ignore
    auth = None  # type: ignore
    credentials = None  # type: ignore

logger = logging.getLogger(__name__)

# Initialize Firebase Admin if not disabled
# This is a centralized initialization to prevent multiple initializations
def initialize_firebase_admin():
    # FIRESTORE_DISABLED only disables Firestore, NOT Firebase Auth
    # We still need Firebase Auth for user authentication
    firestore_disabled = str(os.environ.get('FIRESTORE_DISABLED', '0')).strip().lower()
    if firestore_disabled in {"1", "true", "yes", "on"}:
        logger.info(f"Firestore is disabled (FIRESTORE_DISABLED={firestore_disabled}), but initializing Firebase Auth")
    if firebase_admin is None:
        logger.error("Firebase Admin SDK not imported")
        return None
    if credentials is None:
        logger.error("Firebase credentials module not imported")
        return None
    try:
        app = firebase_admin.get_app()
        logger.info("Firebase Admin already initialized")
        return app
    except Exception as e:
        logger.info(f"Firebase Admin not initialized yet, initializing now: {e}")
        # Check for credentials file
        try:
            cred_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
            if cred_path:
                if os.path.exists(cred_path):
                    logger.info(f"Initializing Firebase with credentials file: {cred_path}")
                    cred = credentials.Certificate(cred_path)
                    app = firebase_admin.initialize_app(cred)
                    logger.info("Firebase Admin initialized successfully with credentials file")
                    return app
                else:
                    logger.error(f"Credentials file not found: {cred_path}")
            else:
                logger.info("GOOGLE_APPLICATION_CREDENTIALS not set, trying application default")
            # Use application default credentials
            app = firebase_admin.initialize_app()
            logger.info("Firebase Admin initialized successfully with application default credentials")
            return app
        except Exception as init_error:
            # If initialization fails, return None and rely on dummy objects below
            logger.error(f"Firebase Admin initialization failed: {init_error}")
            return None

# Initialize Firebase Admin (may be None when disabled)
default_app = initialize_firebase_admin()

# Export Firebase Admin auth for authentication (None when disabled)
if default_app is not None and auth is not None:
    admin_auth = auth
    logger.info("Firebase Admin Auth is available")
else:
    admin_auth = None
    if default_app is None:
        logger.warning("Firebase Admin Auth is NOT available: default_app is None")
    if auth is None:
        logger.warning("Firebase Admin Auth is NOT available: auth module is None")

# Forward declarations for circular references
class DummyAdminCollection:
    pass

class DummyAdminDocument:
    pass

class DummyAdminDocumentSnapshot:
    pass

class DummyAdminDocumentReference:
    pass

class DummyAdminQuery:
    pass

class DummyAdminBatch:
    pass

class DummyAdminTransaction:
    pass

# Dummy document reference class
class DummyAdminDocumentReference:
    def __init__(self, path: str):
        self.path = path
        self.id = path.split('/')[-1] if '/' in path else path
        
    def get(self):
        logger.warning(f"Attempted to get removed Firestore document: {self.path}")
        return DummyAdminDocumentSnapshot(self.path, {})
        
    def set(self, data, merge=False):
        logger.warning(f"Attempted to set removed Firestore document: {self.path}")
        return self
        
    def update(self, data):
        logger.warning(f"Attempted to update removed Firestore document: {self.path}")
        return self
        
    def delete(self):
        logger.warning(f"Attempted to delete removed Firestore document: {self.path}")
        return self
        
    def collection(self, name: str):
        return DummyAdminCollection(f"{self.path}/{name}")

# Dummy document snapshot class
class DummyAdminDocumentSnapshot:
    def __init__(self, path: str, data: Dict[str, Any]):
        self.path = path
        self.id = path.split('/')[-1] if '/' in path else path
        self._data = data
        self.reference = DummyAdminDocumentReference(path)
        
    def exists(self):
        return False
        
    def to_dict(self):
        return {}
        
    def get(self, field_path):
        return None

# Dummy query class
class DummyAdminQuery:
    def __init__(self, collection_name: str):
        self.collection_name = collection_name
        
    def where(self, field: str, op: str, value: Any):
        return self
        
    def order_by(self, field: str, direction=None):
        return self
        
    def limit(self, count: int):
        return self
        
    def offset(self, count: int):
        return self
        
    def get(self):
        return []
        
    def stream(self):
        return []

# Dummy document class
class DummyAdminDocument:
    def __init__(self, path: str):
        self.path = path
        self.id = path.split('/')[-1] if '/' in path else path
        
    def get(self):
        logger.warning(f"Attempted to get removed Firestore document: {self.path}")
        return DummyAdminDocumentSnapshot(self.path, {})
        
    def set(self, data, merge=False):
        logger.warning(f"Attempted to set removed Firestore document: {self.path}")
        return self
        
    def update(self, data):
        logger.warning(f"Attempted to update removed Firestore document: {self.path}")
        return self
        
    def delete(self):
        logger.warning(f"Attempted to delete removed Firestore document: {self.path}")
        return self
        
    def collection(self, name: str):
        return DummyAdminCollection(f"{self.path}/{name}")
        
    def collections(self):
        logger.warning(f"Attempted to list collections in removed Firestore document: {self.path}")
        return []

# Dummy batch class
class DummyAdminBatch:
    def __init__(self):
        logger.warning("Using dummy Firebase Admin Firestore batch. All operations will be no-ops.")
        
    def set(self, reference, data, merge=False):
        logger.warning(f"Attempted to batch set document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def update(self, reference, data):
        logger.warning(f"Attempted to batch update document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def delete(self, reference):
        logger.warning(f"Attempted to batch delete document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def commit(self):
        logger.warning("Attempted to commit batch operations")
        return []

# Dummy transaction class
class DummyAdminTransaction:
    def __init__(self):
        logger.warning("Using dummy Firebase Admin Firestore transaction. All operations will be no-ops.")
        
    def set(self, reference, data, merge=False):
        logger.warning(f"Attempted to transaction set document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def update(self, reference, data):
        logger.warning(f"Attempted to transaction update document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def delete(self, reference):
        logger.warning(f"Attempted to transaction delete document: {getattr(reference, 'path', 'unknown')}")
        return self
        
    def get(self, reference):
        logger.warning(f"Attempted to transaction get document: {getattr(reference, 'path', 'unknown')}")
        return DummyAdminDocumentSnapshot(getattr(reference, 'path', 'unknown'), {})

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

# Implement DummyAdminCollection after all classes are defined
class DummyAdminCollection:
    def __init__(self, name: str):
        self.name = name
    
    def document(self, doc_id: str = None):
        return DummyAdminDocument(f"{self.name}/{doc_id}" if doc_id else self.name)
        
    def list_documents(self):
        logger.warning(f"Listing documents in removed Firestore collection: {self.name}")
        return []
        
    def where(self, field: str, op: str, value: Any):
        return DummyAdminQuery(self.name)
        
    def order_by(self, field: str, direction=None):
        return DummyAdminQuery(self.name)
        
    def limit(self, count: int):
        return DummyAdminQuery(self.name)
        
    def get(self):
        return []
        
    def stream(self):
        return []
        
    def add(self, document_data, document_id=None):
        logger.warning(f"Attempted to add document to removed Firestore collection: {self.name}")
        return DummyAdminDocumentReference(f"{self.name}/{document_id or 'dummy-id'}")

# Do not expose any Firestore client; remove Firestore entirely from runtime
admin_firestore = None
firestore = None