import importlib
import io
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from dedsec.core.contracts import ModuleResult, ScanConfig


class PerThreadCapture(io.TextIOBase):
    def __init__(self, real_stdout):
        self._real = real_stdout

    def write(self, s):
        return self._real.write(s)

    def flush(self):
        return self._real.flush()


def run_modules(
    selected_modules: List[str],
    module_map: Dict[str, Tuple[str, str]],
    url: str,
    domain: str,
    config: ScanConfig,
    on_update: Optional[Callable[[ModuleResult], None]] = None,
) -> Tuple[Dict[str, Any], List[ModuleResult]]:
    results = {}
    module_results = []

    def _worker(module_key: str) -> ModuleResult:
        module_path, label = module_map[module_key]
        if on_update:
            on_update(ModuleResult(module=module_key, label=label, status="running", duration=0.0))

        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf

        start_time = time.time()
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
            duration = time.time() - start_time
            output = buf.getvalue()

        res = ModuleResult(
            module=module_key,
            label=label,
            status=status,
            duration=duration,
            output=output,
            error=err_msg,
            data=data if isinstance(data, dict) else {},
        )

        if on_update:
            on_update(res)

        return res

    max_workers = min(config.concurrency, len(selected_modules))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_worker, module_key): module_key for module_key in selected_modules}

        start_global = time.time()
        for future in as_completed(future_map):
            module_key = future_map[future]
            module_path, label = module_map[module_key]

            if config.global_timeout:
                elapsed = time.time() - start_global
                if elapsed >= config.global_timeout:
                    res = ModuleResult(
                        module=module_key,
                        label=label,
                        status="timeout",
                        duration=elapsed,
                        output="",
                        error="Global scan timeout exceeded",
                    )
                    module_results.append(res)
                    results[module_key] = {"error": "Global scan timeout exceeded"}
                    continue

            try:
                item = future.result()
                module_results.append(item)
                results[item.module] = item.data
            except TimeoutError:
                res = ModuleResult(
                    module=module_key,
                    label=label,
                    status="timeout",
                    duration=config.module_timeout or config.timeout,
                    output="",
                    error="Module timeout exceeded",
                )
                module_results.append(res)
                results[module_key] = {"error": "Module timeout exceeded"}
            except Exception as exc:
                res = ModuleResult(
                    module=module_key,
                    label=label,
                    status="failed",
                    duration=0.0,
                    output="",
                    error=str(exc),
                )
                module_results.append(res)
                results[module_key] = {"error": str(exc)}

    return results, module_results
