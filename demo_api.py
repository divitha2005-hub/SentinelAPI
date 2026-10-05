"""Deliberately vulnerable demo API (for testing SentinelAPI ONLY). Run: uvicorn demo_api:app"""
import sqlite3, threading
from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Vulnerable Demo")
db = sqlite3.connect(":memory:", check_same_thread=False)
lock = threading.Lock()          # sqlite connection is shared across worker threads
db.execute("create table users(id integer, name text)")
db.execute("insert into users values (1,'alice')")


@app.get("/users/search", responses={200: {}, 400: {}})
def search(name: str):                          # SQL injection: string concatenation
    try:
        with lock:
            rows = db.execute(f"select id,name from users where name = '{name}'").fetchall()
    except sqlite3.Error as e:
        raise HTTPException(500, f"sqlite3.Error: {e}")
    return {"results": [{"id": r[0], "name": r[1]} for r in rows]}


@app.get("/greet", response_class=HTMLResponse)
def greet(name: str):                           # reflected XSS
    return f"<h1>Hello {name}</h1>"


@app.get("/files")
def files(path: str):                           # path traversal (simulated)
    if "etc/passwd" in path:
        return {"content": "root:x:0:0:root:/root:/bin/bash"}
    return {"content": ""}


class Item(BaseModel):
    qty: int = 1
    note: str = ""


@app.post("/orders")
def order(item: dict):                          # no validation: accepts anything
    return {"id": 1, "qty": item.get("qty")}


@app.get("/safe/{item_id}")
def safe(item_id: int):                         # properly validated by FastAPI
    return {"id": item_id}


@app.post("/login")
def login(creds: dict):
    if creds.get("user") == "admin" and creds.get("password") == "secret":
        return {"access_token": "tok123"}
    raise HTTPException(401, "bad credentials")


@app.get("/me", responses={200: {}, 401: {}})
def me(authorization: str = Header(default="")):
    if authorization != "Bearer tok123":
        raise HTTPException(401, "unauthorized")
    return {"user": "admin"}


@app.post("/feedback")
def feedback(comment: str = Form(...)):          # form-encoded body, reflected unescaped
    return {"echo": comment}
