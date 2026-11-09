---
name: log-exception-info
description: Coding standard requiring that when catching exceptions with `except Exception as exc:` or similar, errors must be logged by passing `exc_info=exc` (or `exc_info=True`) to the logger method.
---

# Log Exception Info

Always pass the caught exception to `exc_info` when logging errors inside an `except` block.

## Rule

When catching an exception using `except Exception as exc:` (or any specific exception type):
- **DO NOT** format the exception only into the log message string (e.g. `logger.error("Failed: %s", exc)` or `logger.warning(f"Error: {exc}")`) without trace information.
- **DO** include `exc_info=exc` (or `logger.exception(...)`, which implies `exc_info=True`) so that the traceback and full error context are preserved in log outputs.

## Examples

### Bad
```python
try:
    process_item(item)
except Exception as exc:
    logger.error("Failed to process item: %s", exc)
```

### Good
```python
try:
    process_item(item)
except Exception as exc:
    logger.error("Failed to process item: %s", exc, exc_info=exc)
```

Or using `logger.warning`:
```python
try:
    response = await client.get(url)
except Exception as exc:
    logger.warning("Request failed: %s", exc, exc_info=exc)
```
