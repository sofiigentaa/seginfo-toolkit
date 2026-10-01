"""Tests para app/services.py::verify_current_totp (funcion pura, solo
pyotp -- sin DB, sin red).

Cubre el fix de seguridad en /auth/mfa/enroll: antes de este cambio,
re-enrolar MFA (generar un secret nuevo) no exigia probar que quien lo
pedia controlaba el secret ACTUAL, asi que un access_token robado
alcanzaba para tomar el segundo factor de otro usuario. Ahora
mfa_enroll llama a esta funcion para exigir un codigo TOTP valido del
secret vigente antes de reemplazarlo -- estos tests fijan su
comportamiento."""
from types import SimpleNamespace

import pyotp

from app.services import verify_current_totp


def _user(mfa_secret: str | None):
    # No hace falta un modelo SQLAlchemy real (ni sesion, ni DB) --
    # verify_current_totp solo lee el atributo mfa_secret.
    return SimpleNamespace(mfa_secret=mfa_secret)


class TestVerifyCurrentTotp:
    def test_valid_code_for_current_secret_passes(self):
        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        assert verify_current_totp(_user(secret), code) is True

    def test_wrong_code_fails(self):
        secret = pyotp.random_base32()
        other_secret = pyotp.random_base32()
        wrong_code = pyotp.TOTP(other_secret).now()
        assert verify_current_totp(_user(secret), wrong_code) is False

    def test_no_totp_code_fails(self):
        secret = pyotp.random_base32()
        assert verify_current_totp(_user(secret), None) is False
        assert verify_current_totp(_user(secret), "") is False

    def test_user_without_mfa_secret_fails_even_with_a_code(self):
        # Cubre el caso de un primer enrolamiento sin secret todavia --
        # no hay nada "actual" contra lo que verificar.
        assert verify_current_totp(_user(None), "123456") is False

    def test_attacker_guessing_a_new_secret_cannot_pass_as_the_current_one(self):
        # El escenario del bug original: un atacante con un access_token
        # robado NO conoce el secret actual de la victima -- generar su
        # propio secret nuevo y su propio codigo no alcanza para pasar la
        # verificacion contra el secret vigente.
        victim_secret = pyotp.random_base32()
        attacker_secret = pyotp.random_base32()
        attacker_code = pyotp.TOTP(attacker_secret).now()
        assert verify_current_totp(_user(victim_secret), attacker_code) is False
