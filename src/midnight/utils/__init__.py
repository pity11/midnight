"""midnight.utils package."""

from midnight.utils.flag import extract_flags, flag_pattern, looks_like_flag
from midnight.utils.logging import get_logger

__all__ = ["extract_flags", "flag_pattern", "get_logger", "looks_like_flag"]
