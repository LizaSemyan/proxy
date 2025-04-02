from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/requests")
def list_requests():
    raise HTTPException(status_code=501, detail="Not implemented yet")

@app.get("/requests/{id}")
def get_request_detail(id: int):
    raise HTTPException(status_code=501, detail="Not implemented yet")

@app.post("/repeat/{id}")
def repeat_request(id: int):
    raise HTTPException(status_code=501, detail="Not implemented yet")

@app.post("/scan/{id}")
def scan_request(id: int):
    raise HTTPException(status_code=501, detail="Not implemented yet")