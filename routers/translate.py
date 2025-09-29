from typing import List, Optional, Union
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# deep-translator providers
try:
    from deep_translator import (
        GoogleTranslator,
        DeeplTranslator,
        LibreTranslator,
        MicrosoftTranslator,
        MyMemoryTranslator,
    )
except Exception as e:
    # If dependency is missing at runtime, endpoints will raise
    GoogleTranslator = DeeplTranslator = LibreTranslator = MicrosoftTranslator = MyMemoryTranslator = None  # type: ignore

router = APIRouter(prefix="/api/translate", tags=["translate"]) 

class TranslateRequest(BaseModel):
    source: Optional[str] = Field(default="auto", description="Source language code or 'auto'")
    target: str = Field(..., description="Target language code, e.g., 'es'")
    text: Union[str, List[str]] = Field(..., description="Text or list of texts to translate")
    provider: Optional[str] = Field(default="google", description="Provider id: google|deepl|libre|microsoft|mymemory")

class TranslationItem(BaseModel):
    original: str
    translated: str

class TranslateResponse(BaseModel):
    provider: str
    source: str
    target: str
    items: List[TranslationItem]

_SUPPORTED = {"google", "deepl", "libre", "microsoft", "mymemory"}


def _ensure_dependency():
    if GoogleTranslator is None:
        raise HTTPException(status_code=500, detail="Translation dependency not installed. Please add 'deep-translator' to requirements and deploy.")


def _make_translator(provider: str, source: str, target: str):
    p = (provider or "google").strip().lower()
    if p not in _SUPPORTED:
        p = "google"
    # Some providers require API keys via env vars (e.g., DeepL, Microsoft).
    # For initial integration, prefer Google, Libre, or MyMemory which can work without keys (subject to rate limits).
    if p == "google":
        return GoogleTranslator(source=source, target=target)
    if p == "deepl":
        return DeeplTranslator(source=source, target=target)
    if p == "libre":
        return LibreTranslator(source=source, target=target)
    if p == "microsoft":
        return MicrosoftTranslator(source=source, target=target)
    if p == "mymemory":
        return MyMemoryTranslator(source=source, target=target)
    # Fallback
    return GoogleTranslator(source=source, target=target)


@router.post("/", response_model=TranslateResponse)
async def translate(payload: TranslateRequest):
    """
    Translate text using deep-translator providers.

    Example payloads:
    - {"source":"en","target":"es","text":"Good morning"}
    - {"source":"auto","target":"fr","text":["Hello","How are you?"],"provider":"google"}
    """
    _ensure_dependency()

    source = (payload.source or "auto").strip().lower()
    target = (payload.target or "").strip().lower()
    if not target:
        raise HTTPException(status_code=400, detail="'target' is required")

    provider = (payload.provider or "google").strip().lower()
    try:
        translator = _make_translator(provider, source=source, target=target)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to initialize translator: {e}")

    texts: List[str]
    if isinstance(payload.text, list):
        texts = [str(t) for t in payload.text]
    else:
        texts = [str(payload.text)]

    results: List[TranslationItem] = []
    try:
        for t in texts:
            if not t:
                results.append(TranslationItem(original=t, translated=""))
                continue
            translated = translator.translate(t)
            results.append(TranslationItem(original=t, translated=str(translated)))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Translation failed: {e}")

    return TranslateResponse(provider=provider, source=source, target=target, items=results)


@router.get("/providers")
async def list_providers():
    return {"providers": sorted(list(_SUPPORTED))}
