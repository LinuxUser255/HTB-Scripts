"""burp_anon - pseudonymize sensitive data in Burp Suite requests/responses.

Consistent, reversible redaction so HTTP traffic can be shared with an LLM
without leaking client data. See README.md for usage.
"""
from .mapping import Mapping
from .config import load_config, DEFAULT_CONFIG
from .anonymizer import Anonymizer

__version__ = "0.1.0"
__all__ = ["Mapping", "Anonymizer", "load_config", "DEFAULT_CONFIG", "__version__"]
