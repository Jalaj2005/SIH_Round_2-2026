"""Module 1 - Passive ingest, packet parser, flow builder, centralized feature extraction.

SIH 26145 / NTRO unidirectional passive cyber-threat sentinel.
Everything here is strictly receive-only: nothing in this package ever opens a
socket for sending, answers a handshake, or probes a host.
"""
__version__ = "0.1.0"
from .config import Config
from .pipeline import Module1
from .dispatch import Dispatcher, iter_records, ROUTES
