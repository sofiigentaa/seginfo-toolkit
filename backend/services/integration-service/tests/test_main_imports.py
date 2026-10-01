"""Test de wiring de app/main.py: PATCH/DELETE /connectors usan
HTTPException(status_code=404, ...) cuando el conector no existe (ver
update_connector/delete_connector), pero el import de FastAPI en main.py
no lo traia (`from fastapi import FastAPI, Depends, status`) -- una
request real a un connector_id inexistente nunca devolvia el 404
esperado: tiraba un NameError sin manejar (500) antes de llegar a
construir la HTTPException. Sin DB ni red: solo inspecciona el modulo ya
importado (conftest.py deja `app.main` importable sin necesitar un
Postgres real, las conexiones de SQLAlchemy son lazy)."""
from fastapi import HTTPException
from app import main


def test_http_exception_is_imported_in_main():
    assert main.HTTPException is HTTPException
