#!/usr/bin/env python3
"""Local launcher for the HIDEN platform (no Docker), single process."""
import uvicorn
from app.main import app
from app.core.config import PRODUCT

if __name__ == "__main__":
    print(f"  {PRODUCT['name']} by {PRODUCT['vendor']} · http://127.0.0.1:8000", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
