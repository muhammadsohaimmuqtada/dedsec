import importlib
import io
import multiprocessing
import queue
import sys
import threading
import time
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from dedsec.core.contracts import ModuleResult, ScanConfig
from dedsec.core.evidence import EvidenceStore
from dedsec.core.health import TargetHealth
from dedsec.core.module_contract import RUNTIME_ENTRYPOINT
from dedsec.core.module_profiles import TARGET_HTTP_REQUIRED
from dedsec.core.reliability import CircuitBreaker, RetryPolicy, classify_failure
from dedsec.core.runtime import RequestBudget, ScanContext
from dedsec.core.scope import ScopePolicy
from dedsec.core.utils import (
    bind_scan_context,
    configure_http_session,
    unbind_scan_context,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class PerThreadCapture(io.TextIOBase):
    """A stdout proxy that captures output only when the calling thread opted in."""

    def __init__(self, real_stdout):
        self._real = real_stdout
        self._local = threading.local()

    def write(self, value):
        buffer = getattr(self._local, "buffer", None)
        if buffer is not None:
            return buffer.write(value)
        return self._real.write(value)

    def flush(self):
        buffer = getattr(self._local, "buffer", None)
        if buffer is not None:
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


def _mp_context():
    methods = multiprocessing.get_all_start_methods()
    return multiprocessing.get_context("fork" if "fork" in methods else "spawn")


def _runtime_spec(scan_context: Optional[ScanContext]) -> Optional[Dict[str, Any]]:
    if scan_context is None:
        return None
    scope = scan_context.scope
    health = scan_context.target_health
    return {
        "scan_id": scan_context.scan_id,
        "target_url": scan_context.target_url,
        "domain": scan_context.domain,
        "timeout": scan_context.timeout,
        "max_requests": scan_context.request_budget.max_requests,
        "scope": {
            "root_domain": scope.root_domain,
            "allowed_hosts": sorted(scope.allowed_hosts),
            "denied_hosts": sorted(scope.denied_hosts),
            "allowed_ports": sorted(scope.allowed_ports) if scope.allowed_ports is not None else None,
            "allowed_schemes": sorted(scope.allowed_schemes),
            "include_subdomains": scope.include_subdomains,
        },
        "health": {
            "failure_threshold": health.failure_threshold if health is not None else 2,
            "cooldown_seconds": health.cooldown_seconds if health is not None else 15.0,
        },
    }


def _build_child_context(
    runtime_spec,
    shared_counter=None,
    shared_budget_lock=None,
    shared_health_state=None,
    shared_health_failures=None,
    shared_health_successes=None,
    shared_health_last_failure=None,
    shared_health_last_failure_at=None,
    shared_health_lock=None,
):
    if runtime_spec is None:
        return None
    spec = runtime_spec["scope"]
    scope = ScopePolicy(
        root_domain=spec["root_domain"],
        allowed_hosts=set(spec["allowed_hosts"]),
        denied_hosts=set(spec["denied_hosts"]),
        allowed_ports=set(spec["allowed_ports"]) if spec["allowed_ports"] is not None else None,
        allowed_schemes=set(spec["allowed_schemes"]),
        include_subdomains=spec["include_subdomains"],
    )
    evidence = EvidenceStore(scan_id=runtime_spec["scan_id"])
    budget = RequestBudget(
        max_requests=runtime_spec["max_requests"],
        shared_counter=shared_counter,
        shared_lock=shared_budget_lock,
    )
    health_spec = runtime_spec.get("health", {})
    target_health = TargetHealth(
        runtime_spec["domain"],
        failure_threshold=health_spec.get("failure_threshold", 2),
        cooldown_seconds=health_spec.get("cooldown_seconds", 15.0),
        shared_state=shared_health_state,
        shared_failures=shared_health_failures,
        shared_successes=shared_health_successes,
        shared_last_failure=shared_health_last_failure,
        shared_last_failure_at=shared_health_last_failure_at,
        shared_lock=shared_health_lock,
    )
    return ScanContext(
        scan_id=runtime_spec["scan_id"],
        target_url=runtime_spec["target_url"],
        domain=runtime_spec["domain"],
        scope=scope,
        evidence=evidence,
        timeout=runtime_spec["timeout"],
        request_budget=budget,
        target_health=target_health,
    )


def _process_module_entry(
    result_queue,
    module_path: str,
    url: str,
    domain: str,
    config: ScanConfig,
    runtime_spec,
    shared_counter=None,
    shared_budget_lock=None,
    shared_health_state=None,
    shared_health_failures=None,
    shared_health_successes=None,
    shared_health_last_failure=None,
    shared_health_last_failure_at=None,
    shared_health_lock=None,
):
    capture = io.StringIO()
    child_context = None
    attempts = 0
    status = "failed"
    error_message = None
    failure_class = None
    data: Dict[str, Any] = {}

    try:
        configure_http_session(
            total_retries=config.retries,
            backoff_factor=config.backoff,
            pool_connections=config.pool_connections,
            pool_maxsize=config.pool_maxsize,
        )
        child_context = _build_child_context(
            runtime_spec,
            shared_counter=shared_counter,
            shared_budget_lock=shared_budget_lock,
            shared_health_state=shared_health_state,
            shared_health_failures=shared_health_failures,
            shared_health_successes=shared_health_successes,
            shared_health_last_failure=shared_health_last_failure,
            shared_health_last_failure_at=shared_health_last_failure_at,
            shared_health_lock=shared_health_lock,
        )
        if child_context is not None:
            bind_scan_context(
                child_context,
                retries=config.retries,
                backoff=config.backoff,
                pool_connections=config.pool_connections,
                pool_maxsize=config.pool_maxsize,
            )

        retry_policy = RetryPolicy(
            retries=config.module_retries,
            base_backoff=config.backoff,
            max_backoff=config.retry_backoff_cap,
        )
        breaker = CircuitBreaker(config.circuit_failure_threshold, config.circuit_cooldown)

        with redirect_stdout(capture):
            for attempt in range(1, retry_policy.max_attempts + 1):
                attempts = attempt
                if not breaker.allow():
                    error_message = "Circuit breaker open after repeated module failures"
                    failure_class = "permanent"
                    break
                try:
                    module = importlib.import_module(module_path)
                    runtime_entrypoint = getattr(module, RUNTIME_ENTRYPOINT, None)
                    if child_context is not None and callable(runtime_entrypoint):
                        raw_data = runtime_entrypoint(child_context)
                    else:
                        raw_data = module.run(url=url, domain=domain, timeout=config.timeout)

                    data = raw_data if isinstance(raw_data, dict) else {}
                    if isinstance(raw_data, dict) and raw_data.get("inconclusive"):
                        status = "inconclusive"
                        error_message = str(
                            raw_data.get("error") or "Module could not obtain enough target data"
                        )
                        failure_class = str(raw_data.get("failure_class") or "inconclusive")
                        break
                    if isinstance(raw_data, dict) and raw_data.get("partial"):
                        status = "partial"
                        error_message = str(raw_data.get("error") or "Module completed with partial data")
                        failure_class = str(raw_data.get("failure_class") or "partial")
                        break
                    if isinstance(raw_data, dict) and raw_data.get("error"):
                        error_message = str(raw_data["error"])
                        if (
                            child_context is not None
                            and child_context.target_health is not None
                            and child_context.target_health.should_short_circuit()
                        ):
                            status = "inconclusive"
                            failure_class = "target_unreachable"
                            break
                        failure_class = classify_failure(error_message)
                        breaker.record_failure()
                        if retry_policy.should_retry(attempt, failure_class):
                            delay = retry_policy.delay_for(attempt)
                            if delay:
                                time.sleep(delay)
                            continue
                        break

                    status = "success"
                    error_message = None
                    failure_class = None
                    breaker.record_success()
                    break
                except Exception as exc:
                    error_message = str(exc) or exc.__class__.__name__
                    if (
                        child_context is not None
                        and child_context.target_health is not None
                        and child_context.target_health.should_short_circuit()
                    ):
                        status = "inconclusive"
                        failure_class = "target_unreachable"
                        break
                    failure_class = classify_failure(error_message)
                    breaker.record_failure()
                    if retry_policy.should_retry(attempt, failure_class):
                        delay = retry_policy.delay_for(attempt)
                        if delay:
                            time.sleep(delay)
                        continue
                    break
    except BaseException as exc:
        error_message = str(exc) or exc.__class__.__name__
        failure_class = classify_failure(error_message)
        status = "failed"
    finally:
        unbind_scan_context()
        if child_context is not None:
            try:
                child_context.close()
            except Exception:
                pass

    try:
        result_queue.put(
            {
                "status": status,
                "data": data,
                "error": error_message,
                "failure_class": failure_class,
                "attempts": max(attempts, 1),
                "output": capture.getvalue(),
            }
        )
    except Exception:
        pass


def _stop_process(process, grace: float = 0.75) -> None:
    if not process.is_alive():
        process.join(timeout=0.05)
        return
    process.terminate()
    process.join(timeout=max(grace, 0.05))
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=max(grace, 0.05))


def run_modules(
    selected_modules: List[str],
    module_map: Dict[str, Tuple[str, str]],
    url: str,
    domain: str,
    config: ScanConfig,
    on_update: Optional[Callable[[ModuleResult], None]] = None,
    evidence_store: Optional[EvidenceStore] = None,
    scan_context: Optional[ScanContext] = None,
) -> Tuple[Dict[str, Any], List[ModuleResult]]:
    """Execute modules under killable process-level hard deadlines."""
    if not selected_modules:
        return {}, []
    if evidence_store is None and scan_context is not None:
        evidence_store = scan_context.evidence

    mp_context = _mp_context()
    runtime_spec = _runtime_spec(scan_context)
    shared_counter = None
    shared_budget_lock = None
    shared_health_state = None
    shared_health_failures = None
    shared_health_successes = None
    shared_health_last_failure = None
    shared_health_last_failure_at = None
    shared_health_lock = None
    scheduler_health = None

    if scan_context is not None:
        shared_counter = mp_context.Value("q", int(scan_context.request_budget.requests_used))
        shared_budget_lock = mp_context.Lock()
        health = scan_context.target_health or TargetHealth(scan_context.domain)
        health_snapshot = health.snapshot()
        shared_health_state = mp_context.Value("i", int(health_snapshot["state_code"]))
        shared_health_failures = mp_context.Value(
            "i", int(health_snapshot["consecutive_failures"])
        )
        shared_health_successes = mp_context.Value("i", int(health_snapshot["successes"]))
        shared_health_last_failure = mp_context.Value("i", int(health.last_failure_code))
        shared_health_last_failure_at = mp_context.Value("d", float(health.last_failure_at))
        shared_health_lock = mp_context.Lock()
        scheduler_health = TargetHealth(
            scan_context.domain,
            failure_threshold=health.failure_threshold,
            cooldown_seconds=health.cooldown_seconds,
            shared_state=shared_health_state,
            shared_failures=shared_health_failures,
            shared_successes=shared_health_successes,
            shared_last_failure=shared_health_last_failure,
            shared_last_failure_at=shared_health_last_failure_at,
            shared_lock=shared_health_lock,
        )

    results: Dict[str, Any] = {}
    result_by_module: Dict[str, ModuleResult] = {}
    pending = list(selected_modules)
    active: Dict[str, Dict[str, Any]] = {}
    global_deadline = (
        time.monotonic() + float(config.global_timeout)
        if config.global_timeout is not None
        else None
    )

    def _persist(result: ModuleResult) -> None:
        if evidence_store is not None and not result.evidence_ids:
            evidence = evidence_store.persist_module_result(result)
            result.evidence_ids.append(evidence.evidence_id)
        result_by_module[result.module] = result
        results[result.module] = (
            result.data if result.data else ({"error": result.error} if result.error else {})
        )
        if on_update:
            on_update(result)

    def _skip_unreachable_http_module(module_key: str) -> bool:
        if module_key not in TARGET_HTTP_REQUIRED or scheduler_health is None:
            return False
        if not scheduler_health.should_short_circuit():
            return False
        _, label = module_map[module_key]
        _persist(
            ModuleResult(
                module=module_key,
                label=label,
                status="inconclusive",
                duration=0.0,
                error="Root target transport is currently unreachable; HTTP-dependent module skipped",
                attempts=0,
                started_at=None,
                failure_class="target_unreachable",
            )
        )
        return True

    def _start(module_key: str) -> None:
        if _skip_unreachable_http_module(module_key):
            return
        module_path, label = module_map[module_key]
        started_at = _utc_now()
        started = time.monotonic()
        result_queue = mp_context.Queue(maxsize=1)
        process = mp_context.Process(
            target=_process_module_entry,
            args=(
                result_queue,
                module_path,
                url,
                domain,
                config,
                runtime_spec,
                shared_counter,
                shared_budget_lock,
                shared_health_state,
                shared_health_failures,
                shared_health_successes,
                shared_health_last_failure,
                shared_health_last_failure_at,
                shared_health_lock,
            ),
            name="dedsec-%s" % module_key,
        )
        process.start()
        active[module_key] = {
            "process": process,
            "queue": result_queue,
            "label": label,
            "started_at": started_at,
            "started": started,
        }
        if on_update:
            on_update(
                ModuleResult(
                    module=module_key,
                    label=label,
                    status="running",
                    duration=0.0,
                    started_at=started_at,
                )
            )

    def _close_queue(result_queue) -> None:
        try:
            result_queue.close()
            result_queue.cancel_join_thread()
        except Exception:
            pass

    def _finish_payload(module_key: str, state: Dict[str, Any], payload: Dict[str, Any]) -> None:
        process = state["process"]
        process.join(timeout=0.2)
        if process.is_alive():
            _stop_process(process)
        result = ModuleResult(
            module=module_key,
            label=state["label"],
            status=payload.get("status", "failed"),
            duration=time.monotonic() - state["started"],
            output=payload.get("output", ""),
            error=payload.get("error"),
            data=payload.get("data") if isinstance(payload.get("data"), dict) else {},
            attempts=int(payload.get("attempts", 1) or 1),
            started_at=state["started_at"],
            failure_class=payload.get("failure_class"),
        )
        _close_queue(state["queue"])
        _persist(result)
        del active[module_key]

    def _finish_terminal(module_key: str, state: Dict[str, Any], status: str, reason: str) -> None:
        _stop_process(state["process"])
        result = ModuleResult(
            module=module_key,
            label=state["label"],
            status=status,
            duration=time.monotonic() - state["started"],
            error=reason,
            attempts=1,
            started_at=state["started_at"],
            failure_class="timeout" if status == "timeout" else "aborted",
        )
        _close_queue(state["queue"])
        _persist(result)
        del active[module_key]

    max_workers = min(max(1, config.concurrency), len(selected_modules))
    abort_reason = None
    abort_status = "aborted"

    try:
        while pending or active:
            now = time.monotonic()
            if global_deadline is not None and now >= global_deadline:
                abort_reason = "Global scan timeout exceeded"
                abort_status = "timeout"
                break

            while pending and len(active) < max_workers:
                if global_deadline is not None and time.monotonic() >= global_deadline:
                    abort_reason = "Global scan timeout exceeded"
                    abort_status = "timeout"
                    break
                _start(pending.pop(0))
            if abort_reason:
                break

            progressed = False
            now = time.monotonic()
            for module_key in list(active):
                state = active.get(module_key)
                if state is None:
                    continue

                try:
                    payload = state["queue"].get_nowait()
                except queue.Empty:
                    payload = None
                if payload is not None:
                    _finish_payload(module_key, state, payload)
                    progressed = True
                    continue

                if (
                    config.module_timeout is not None
                    and now - state["started"] >= float(config.module_timeout)
                ):
                    _finish_terminal(module_key, state, "timeout", "Module hard timeout exceeded")
                    progressed = True
                    continue

                if not state["process"].is_alive():
                    try:
                        payload = state["queue"].get(timeout=0.15)
                    except queue.Empty:
                        payload = {
                            "status": "failed",
                            "data": {},
                            "error": "Module process exited without returning a result",
                            "failure_class": "permanent",
                            "attempts": 1,
                            "output": "",
                        }
                    _finish_payload(module_key, state, payload)
                    progressed = True

            if not progressed:
                time.sleep(0.05)

    except KeyboardInterrupt:
        abort_reason = "Scan aborted by user"
        abort_status = "aborted"
    finally:
        if abort_reason is not None:
            for module_key in list(active):
                state = active.get(module_key)
                if state is not None:
                    _finish_terminal(module_key, state, abort_status, abort_reason)
            while pending:
                module_key = pending.pop(0)
                _, label = module_map[module_key]
                _persist(
                    ModuleResult(
                        module=module_key,
                        label=label,
                        status=abort_status,
                        duration=0.0,
                        error=abort_reason,
                        attempts=0,
                        started_at=None,
                        failure_class="timeout" if abort_status == "timeout" else "aborted",
                    )
                )
        else:
            for module_key in list(active):
                state = active.get(module_key)
                if state is not None:
                    _finish_terminal(module_key, state, "aborted", "Scanner cleanup aborted module")

    if shared_counter is not None and scan_context is not None:
        scan_context.request_budget.set_used(int(shared_counter.value))
    if scheduler_health is not None and scan_context is not None:
        scan_context.target_health.sync_from_values(
            int(shared_health_state.value),
            int(shared_health_failures.value),
            int(shared_health_successes.value),
            int(shared_health_last_failure.value),
            float(shared_health_last_failure_at.value),
        )

    module_results = [
        result_by_module[module_key]
        for module_key in selected_modules
        if module_key in result_by_module
    ]
    return results, module_results
