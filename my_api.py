"""Custom Sample API for testing in SentinelAPI dashboard.
Run with: .\.venv\Scripts\python -m uvicorn my_api:app --host 127.0.0.1 --port 8000
"""
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="My Store API", version="1.0.0")

class Product(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    price: float = Field(..., gt=0)
    in_stock: bool = True

class Feedback(BaseModel):
    author: str
    message: str

# In-memory store
products = [
    {"id": 1, "name": "Laptop", "price": 999.99, "in_stock": True},
    {"id": 2, "name": "Mouse", "price": 25.50, "in_stock": True},
]

@app.get("/products")
def list_products():
    return products

@app.get("/products/{product_id}")
def get_product(product_id: int):
    for p in products:
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")

@app.post("/products", status_code=201)
def create_product(product: Product):
    item = {"id": len(products) + 1, **product.model_dump()}
    products.append(item)
    return item

@app.post("/feedback")
def submit_feedback(fb: Feedback):
    # Simulated flaw: unhandled 500 when message is empty or specific crash input
    if not fb.message or fb.message == "crash":
        raise RuntimeError("Internal crash processing feedback")
    return {"status": "received", "length": len(fb.message)}

@app.get("/admin/profile")
def admin_profile(authorization: str = Header(default="")):
    # Requires Bearer token
    if authorization != "Bearer secret-token-xyz":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"admin": "root", "role": "superadmin"}
