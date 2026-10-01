"""Tests de app/services.py::driver_exception_error_message -- el mensaje
que se guarda en ScanJob.error_message cuando execute_scan_job atrapa una
excepcion no prevista del driver (ver el try/except alrededor de
driver.run() en execute_scan_job: sin el, el job se quedaba en estado
"running" para siempre porque el error escapaba del background task sin
que nadie lo atrapara). Funcion pura, sin DB ni scanner real -- igual que
test_delete_status.py en este mismo paquete."""
from app.services import driver_exception_error_message


class TestDriverExceptionErrorMessage:
    def test_includes_exception_message(self):
        msg = driver_exception_error_message(PermissionError("no se pudo ejecutar el binario"))
        assert "no se pudo ejecutar el binario" in msg

    def test_truncates_to_2000_chars(self):
        exc = RuntimeError("x" * 3000)
        msg = driver_exception_error_message(exc)
        assert len(msg) <= 2000

    def test_prefix_identifies_it_as_a_driver_exception(self):
        msg = driver_exception_error_message(ValueError("boom"))
        assert msg.startswith("Error inesperado del driver de escaneo:")
