"""Run the gateway: python -m gateway.main (from the project root)."""
import uvicorn

from gateway.config import GATEWAY_HOST, GATEWAY_PORT

if __name__ == "__main__":
    uvicorn.run("gateway.server:app", host=GATEWAY_HOST, port=GATEWAY_PORT)
