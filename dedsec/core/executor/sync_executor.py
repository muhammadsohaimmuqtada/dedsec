import importlib
import io
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from dedsec.core.contracts import ScanConfig, ModuleResult

def run_modules_sync(
    selected_modules: List[str],
    module_map: Dict[str, Tuple[str, str]],
    url: str,
    domain: str,
    config: ScanConfig,
    on_update: Optional[Callable[[ModuleResult], None]] = None,
) -> Tuple[Dict[str, Any], List[ModuleResult]]:
    """Synchronous thread-pool module executor."""
    results = {}
    module_results = []

    def _worker(module_key: str):
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
        futures = {executor.submit(_worker, key): key for key in selected_modules}
        for future in as_completed(futures):
            res = future.result()
            module_results.append(res)
            results[res.module] = res.data

    return results, module_results
