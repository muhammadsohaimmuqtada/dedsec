import asyncio
import importlib
import io
import sys
import time
from typing import Dict, Tuple, List, Callable, Optional
from dedsec.core.contracts import ScanConfig, ModuleResult

async def run_module_async(
    module_key: str,
    module_path: str,
    label: str,
    url: str,
    domain: str,
    config: ScanConfig,
) -> ModuleResult:
    """Run a single module asynchronously in an executor thread with capture."""
    loop = asyncio.get_event_loop()

    def _execute():
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        start = time.time()
        status = "failed"
        err_msg = None
        data = {}

        try:
            mod = importlib.import_module(module_path)
            timeout = config.module_timeout or config.timeout
            data = mod.run(url=url, domain=domain, timeout=timeout)
            status = "success"
            if isinstance(data, dict) and "error" in data:
                status = "failed"
                err_msg = str(data["error"])
        except Exception as exc:
            err_msg = str(exc)
            status = "failed"
        finally:
            sys.stdout = old_stdout
            duration = time.time() - start
            output = buf.getvalue()

        return ModuleResult(
            module=module_key,
            label=label,
            status=status,
            duration=duration,
            output=output,
            error=err_msg,
            data=data if isinstance(data, dict) else {},
        )

    return await loop.run_in_executor(None, _execute)
