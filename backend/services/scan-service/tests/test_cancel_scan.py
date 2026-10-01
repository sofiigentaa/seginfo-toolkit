"""Tests de app/services.py: is_cancellable_status (la regla de negocio que
decide que escaneos se pueden cancelar) y el registro en memoria de tareas
en curso (_RUNNING_SCAN_TASKS / register_running_scan / cancel_running_scan)
que usa POST /scans/{id}/cancel para pedirle la cancelacion real a la Task
de asyncio que esta corriendo el driver. Sin DB ni drivers reales -- las
pruebas de registro usan un asyncio.Task minimo (via asyncio.run), en la
misma linea de aislamiento que test_delete_status.py."""
import asyncio
import enum

import pytest

from app.services import (
    cancel_running_scan,
    is_cancellable_status,
    register_running_scan,
    unregister_running_scan,
)


class _FakeStatusEnum(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    scanner_unavailable = "scanner_unavailable"


class TestIsCancellableStatus:
    def test_pending_and_running_are_cancellable(self):
        assert is_cancellable_status("pending") is True
        assert is_cancellable_status("running") is True

    def test_terminal_string_statuses_are_not_cancellable(self):
        assert is_cancellable_status("completed") is False
        assert is_cancellable_status("failed") is False
        assert is_cancellable_status("scanner_unavailable") is False
        assert is_cancellable_status("cancelled") is False

    def test_accepts_enum_members_not_just_strings(self):
        # job.status llega como el enum de SQLAlchemy, no como str plano --
        # is_cancellable_status tiene que manejar ambos (ver hasattr(.., "value")).
        assert is_cancellable_status(_FakeStatusEnum.running) is True
        assert is_cancellable_status(_FakeStatusEnum.completed) is False

    def test_unknown_status_is_not_cancellable(self):
        assert is_cancellable_status("some_future_status") is False


class TestCancelRunningScan:
    def test_cancel_unknown_job_id_returns_false(self):
        # Nadie registro una tarea para este job_id -- ya termino, es de
        # otro proceso, o nunca llego a arrancar. No hay nada que matar.
        assert cancel_running_scan("no-existe") is False

    def test_cancel_requests_cancellation_on_registered_task(self):
        async def scenario():
            async def _sleep_forever():
                await asyncio.sleep(3600)

            task = asyncio.create_task(_sleep_forever())
            register_running_scan("job-cancel-1", task)
            try:
                assert cancel_running_scan("job-cancel-1") is True
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert task.cancelled() is True
            finally:
                unregister_running_scan("job-cancel-1")

        asyncio.run(scenario())

    def test_cancel_returns_false_once_task_already_done(self):
        async def scenario():
            async def _noop():
                return None

            task = asyncio.create_task(_noop())
            register_running_scan("job-cancel-2", task)
            await task  # deja que termine antes de intentar cancelarla
            try:
                assert cancel_running_scan("job-cancel-2") is False
            finally:
                unregister_running_scan("job-cancel-2")

        asyncio.run(scenario())

    def test_unregister_is_safe_to_call_twice(self):
        # execute_scan_job siempre desregistra en un finally, incluso si
        # nunca llego a registrarse (job is None) -- no debe explotar.
        unregister_running_scan("nunca-se-registro")
        unregister_running_scan("nunca-se-registro")
