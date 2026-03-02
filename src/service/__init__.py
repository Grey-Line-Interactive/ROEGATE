"""
ROE Gate Service — HTTP API Server and Client

The Gate Service is the standalone HTTP API that wraps the ROE Gate evaluation
pipeline. It runs as a SEPARATE PROCESS from the agent, holding the signing keys
and serving as the single authority that can approve or deny actions.

Components:
    GateAPIServer: The HTTP server that exposes the Gate evaluation pipeline.
    GateServiceClient: A synchronous HTTP client for communicating with the server.
"""

from .gate_api import GateAPIServer, create_server
from .gate_client import GateServiceClient

__all__ = [
    "GateAPIServer",
    "create_server",
    "GateServiceClient",
]
