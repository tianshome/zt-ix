from fastapi import FastAPI

app = FastAPI(title="ZT-IX Controller", version="0.1.0")


@app.get("/", tags=["system"])
async def root() -> dict[str, str]:
    return {"service": "zt-ix", "status": "ok"}


@app.get("/healthz", tags=["system"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
