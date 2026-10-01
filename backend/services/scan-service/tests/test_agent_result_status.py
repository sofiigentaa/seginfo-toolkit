"""Tests de app/services.py::is_submittable_status -- la regla que decide
si un agente remoto todavia puede reportar el resultado de un
AgentScanJob. Sin DB: solo logica pura, igual que test_delete_status.py en
este mismo paquete.

Sin este chequeo, un doble submit del mismo agente (reintento tras perder
la respuesta del primer POST a /agents/results/{job_id}, o dos procesos de
agente corriendo por error con la misma api key) podia sobreescribir un
resultado ya guardado (completed/failed) y volver a reenviar los mismos
hallazgos a vuln-service/siem-service como si fueran nuevos."""
from app.services import is_submittable_status


class TestIsSubmittableStatus:
    def test_pending_is_submittable(self):
        assert is_submittable_status("pending") is True

    def test_assigned_is_submittable(self):
        assert is_submittable_status("assigned") is True

    def test_completed_is_not_submittable(self):
        assert is_submittable_status("completed") is False

    def test_failed_is_not_submittable(self):
        assert is_submittable_status("failed") is False

    def test_unknown_status_is_not_submittable(self):
        assert is_submittable_status("algo_futuro") is False
