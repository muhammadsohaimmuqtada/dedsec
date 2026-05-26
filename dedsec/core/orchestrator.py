import importlib
import io
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Callable, Dict, Iterable, List, Tuple

from dedsec.core.contracts import ModuleResult, ScanConfig

_thread_buffers = threading.local()


class PerThreadCapture:
    def __init__(self, real_stream):
        self._real = real_stream

    def _target(self):
        return getattr(_thread_buffers, "buf", None) or self._real

    def write(self, data):
        self._target().write(data)

    def flush(self):
        self._target().flush()

    def fileno(self):
        return self._real.fileno()

    def isatty(self):
        return self._real.isatty()


def _execute_module(module_path: str, url: str, domain: str, config: ScanConfig) -> Tuple[Dict, str]:
    buf = io.StringIO()
    _thread_buffers.buf = buf
    try:
        module = importlib.import_module(module_path)
        result = module.run(url, domain, timeout=config.timeout)
    except Exception as exc:
        return {"error": str(exc)}, buf.getvalue()
    finally:
        _thread_buffers.buf = None
    return result, buf.getvalue()


def run_modules(
    selected_modules: Iterable[str],
    module_map: Dict[str, Tuple[str, str]],
    url: str,
    domain: str,
    config: ScanConfig,
    on_update: Callable[[ModuleResult], None] = None,
):
    selected = list(selected_modules)
    if not selected:
        return {}, []

    effective_concurrency = max(1, min(config.concurrency, len(selected)))
    started_at = time.monotonic()

    results: Dict[str, Dict] = {}
    module_results: List[ModuleResult] = []

    with ThreadPoolExecutor(max_workers=effective_concurrency) as executor:
        futures = {
            key: executor.submit(_execute_module, module_map[key][0], url, domain, config)
            for key in selected
        }

        for key in selected:
            _, label = module_map[key]
            event_running = ModuleResult(module=key, label=label, status="running")
            if on_update:
                on_update(event_running)

            finished_status = "success"
            result_data: Dict = {}
            output = ""
            error = None
            module_started = time.monotonic()

            remaining_global = None
            if config.global_timeout is not None:
                elapsed = time.monotonic() - started_at
                remaining_global = max(config.global_timeout - elapsed, 0)

            timeout_budget = config.module_timeout
            if timeout_budget is None:
                timeout_budget = remaining_global
            elif remaining_global is not None:
                timeout_budget = min(timeout_budget, remaining_global)

            try:
                if timeout_budget is not None and timeout_budget <= 0:
                    raise TimeoutError()
                result_data, output = futures[key].result(timeout=timeout_budget)
                if isinstance(result_data, dict) and result_data.get("error"):
                    finished_status = "failed"
                    error = str(result_data["error"])
                elif isinstance(result_data, dict) and not result_data and "could not connect" in output.lower():
                    finished_status = "failed"
                    error = "Could not connect to target"
            except TimeoutError:
                finished_status = "timeout"
                error = "Module execution timed out"
                result_data = {"error": error}
                futures[key].cancel()
            except Exception as exc:
                finished_status = "failed"
                error = str(exc)
                result_data = {"error": error}

            event_done = ModuleResult(
                module=key,
                label=label,
                status=finished_status,
                duration=time.monotonic() - module_started,
                result=result_data,
                output=output,
                error=error,
            )
            results[key] = result_data
            module_results.append(event_done)
            if on_update:
                on_update(event_done)

    return results, module_results
