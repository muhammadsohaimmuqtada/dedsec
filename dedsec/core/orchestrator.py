import importlib
import io
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from dedsec.core.contracts import ModuleResult, ScanConfig
from dedsec.core.evidence import EvidenceStore
from dedsec.core.reliability import CircuitBreaker, RetryPolicy, classify_failure


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class PerThreadCapture(io.TextIOBase):
    """A stdout proxy that captures only the current worker thread."""

    def __init__(self, real_stdout):
        self._real = real_stdout
        self._local = threading.local()

    def write(self, s):
        buf = getattr(self._local, "buffer", None)
        if buf is not None:
            return buf.write(s)
        return self._real.write(s)

    def flush(self):
        buf = getattr(self._local, "buffer", None)
        if buf is not None:
            return None
        return self._real.flush()

    @contextmanager
    def capture(self):
        previous = getattr(self._local, "buffer", None)
        current = io.StringIO()
        self._local.buffer = current
        try:
            yield current
        finally:
            if previous is None:
                try:
                    del self._local.buffer
                except AttributeError:
                    pass
            else:
                self._local.buffer = previous


def run_modules(
    selected_modules: List[str],
    module_map: Dict[str, Tuple[str, str]],
    url: str,
    domain: str,
    config: ScanConfig,
    on_update: Optional[Callable[[ModuleResult], None]] = None,
    evidence_store: Optional[EvidenceStore] = None,
) -> Tuple[Dict[str, Any], List[ModuleResult]]:
    if not selected_modules:
        return {}, []

    results: Dict[str, Any] = {}
    module_results: List[ModuleResult] = []
    retry_policy = RetryPolicy(
        retries=config.module_retries,
        base_backoff=config.backoff,
        max_backoff=config.retry_backoff_cap,
    )
    breakers = {
        key: CircuitBreaker(config.circuit_failure_threshold, config.circuit_cooldown)
        for key in selected_modules
    }

    def _capture_context():
        current_stdout = sys.stdout
        if isinstance(current_stdout, PerThreadCapture):
            return current_stdout.capture()

        @contextmanager
        def _empty_capture():
            yield io.StringIO()

        return _empty_capture()

    def _worker(module_key: str) -> ModuleResult:
        module_path, label = module_map[module_key]
        if on_update:
            on_update(ModuleResult(module=module_key, label=label, status="running", duration=0.0))

        started_at = _utc_now()
        start_time = time.monotonic()
        status = "failed"
        err_msg: Optional[str] = None
        data: Dict[str, Any] = {}
        failure_class: Optional[str] = None
        attempts = 0

        with _capture_context() as buf:
            for attempt in range(1, retry_policy.max_attempts + 1):
                attempts = attempt
                if not breakers[module_key].allow():
                    err_msg = "Circuit breaker open after repeated module failures"
                    failure_class = "permanent"
                    break

                try:
                    mod = importlib.import_module(module_path)
                    timeout = config.module_timeout or config.timeout
                    raw_data = mod.run(url=url, domain=domain, timeout=timeout)
                    data = raw_data if isinstance(raw_data, dict) else {}
                    if isinstance(raw_data, dict) and raw_data.get("error"):
                        err_msg = str(raw_data["error"])
                        failure_class = classify_failure(err_msg)
                        breakers[module_key].record_failure()
                        if retry_policy.should_retry(attempt, failure_class):
                            delay = retry_policy.delay_for(attempt)
                            if delay:
                                time.sleep(delay)
                            continue
                        status = "failed"
                        break

                    status = "success"
                    err_msg = None
                    failure_class = None
                    breakers[module_key].record_success()
                    break
                except Exception as exc:
                    err_msg = str(exc)
                    failure_class = classify_failure(err_msg)
                    breakers[module_key].record_failure()
                    if retry_policy.should_retry(attempt, failure_class):
                        delay = retry_policy.delay_for(attempt)
                        if delay:
                            time.sleep(delay)
                        continue
                    status = "failed"
                    break

            duration = time.monotonic() - start_time
            output = buf.getvalue()

        if config.module_timeout and duration > config.module_timeout and status != "failed":
            status = "timeout"
            err_msg = "Module exceeded configured timeout before returning"
            failure_class = "timeout"

        result = ModuleResult(
            module=module_key,
            label=label,
            status=status,
            duration=duration,
            output=output,
            error=err_msg,
            data=data,
            attempts=attempts,
            started_at=started_at,
            failure_class=failure_class,
        )

        if evidence_store is not None:
            evidence = evidence_store.persist_module_result(result)
            result.evidence_ids.append(evidence.evidence_id)

        if on_update:
            on_update(result)
        return result

    max_workers = min(max(1, config.concurrency), len(selected_modules))
    executor = ThreadPoolExecutor(max_workers=max_workers)
    future_map = {executor.submit(_worker, module_key): module_key for module_key in selected_modules}
    unfinished = set(future_map)

    try:
        iterator = as_completed(future_map, timeout=config.global_timeout)
        for future in iterator:
            unfinished.discard(future)
            module_key = future_map[future]
            _, label = module_map[module_key]
            try:
                item = future.result()
            except Exception as exc:
                item = ModuleResult(
                    module=module_key,
                    label=label,
                    status="failed",
                    duration=0.0,
                    error=str(exc),
                    failure_class=classify_failure(str(exc)),
                )
                if evidence_store is not None:
                    evidence = evidence_store.persist_module_result(item)
                    item.evidence_ids.append(evidence.evidence_id)
            module_results.append(item)
            results[item.module] = (
                item.data if item.data else ({"error": item.error} if item.error else {})
            )
    except TimeoutError:
        for future in list(unfinished):
            module_key = future_map[future]
            _, label = module_map[module_key]
            future.cancel()
            item = ModuleResult(
                module=module_key,
                label=label,
                status="timeout",
                duration=float(config.global_timeout or 0),
                error="Global scan timeout exceeded",
                failure_class="timeout",
            )
            if evidence_store is not None:
                evidence = evidence_store.persist_module_result(item)
                item.evidence_ids.append(evidence.evidence_id)
            module_results.append(item)
            results[module_key] = {"error": "Global scan timeout exceeded"}
            if on_update:
                on_update(item)
    finally:
        for pending_future in unfinished:
            pending_future.cancel()
        executor.shutdown(wait=True)

    module_results.sort(key=lambda item: selected_modules.index(item.module))
    return results, module_results
