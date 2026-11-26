"""API pública de solo lectura (CMP-002). Ver `vs.api.app`."""

from vs.api.app import ApiConfig, ApiConfigError, api_audience, create_app

__all__ = ["ApiConfig", "ApiConfigError", "api_audience", "create_app"]
