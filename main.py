from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routers (package-relative imports)
from .routers.core import router as core_router  # type: ignore
from .routers.builder import router as builder_router  # type: ignore

app = FastAPI(title="CleanEnroll API")

# CORS (embedding and local development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(core_router)
app.include_router(builder_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
