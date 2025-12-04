#!/usr/bin/env python3
"""
Regression Test: Mitigación de inyección SQL

Este test basicamente se encarga de validar que la inyección SQL en el invoice haya sido mitigada. En main se usa concatenación de strings en las consultas SQL lo cual
deja expuesto a que se haga inyección SQL a través del status u operadores.

La idea es mitigarlo con una lista de operadores permitidos, hacer validación de lo que se ingrese como status y parametrizar las consultas usando knex en vez de estar
concatenando el string de forma directa. El test intenta cargar varios payloads con inyección SQL que en la versión vulnerable deberían lograr penetrar. Verifica luego
que todos sean rechazados y que las consultas legitimas sigan funcionando.
"""

import requests
import json
import sys
import urllib.parse
import pytest

# Configuration
BASE_URL = "http://localhost:5000"
USERNAME = "test"
PASSWORD = "password"


class TestSQLInjectionRegression:

    @pytest.fixture(scope="class")
    def auth_token(self):
        url = f"{BASE_URL}/auth/login"
        data = {"username": USERNAME, "password": PASSWORD}

        try:
            response = requests.post(url, json=data)
            assert response.status_code == 200, f"Login failed: {response.status_code}"
            token = response.json()["token"]
            assert token, "No token received"
            return token
        except Exception as e:
            pytest.fail(f"Authentication failed: {e}")

    def test_basic_sql_injection_payloads_rejected(self, auth_token):
        malicious_payloads = [
            ("paid' OR '1'='1", "=", "Bypass authentication"),
            ("paid' UNION SELECT 1,2,3,4,5--", "=", "Basic UNION injection"),
            ("paid'; DROP TABLE invoices; --", "=", "Destructive injection"),
            ("paid' UNION SELECT table_name,column_name,data_type,null,null FROM information_schema.columns--", "=", "Schema extraction"),
            ("paid' AND 1=1", "=", "Logic bypass"),
            ("paid' AND 1=2", "=", "Logic bypass negative"),
            ("paid' OR 1=1--", "=", "Comment injection"),
            ("paid' /*", "=", "Block comment"),
            ("paid' || 'test'", "=", "Concatenation injection"),
            ("paid'; SELECT * FROM users--", "=", "Multi-statement injection"),
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status, operator, description in malicious_payloads:
            print(f"\nTesting: {description}")
            encoded_status = urllib.parse.quote(status)
            encoded_operator = urllib.parse.quote(operator)

            url = f"{BASE_URL}/invoices?status={encoded_status}&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)
                assert response.status_code != 200, f"Inyeccion SQL exitosa {description}: {response.status_code}"

                #A partir de aca deberia ocurrir un error de validación o directamente dar 500
                if response.status_code == 400:
                    #Error de validacion
                    error_data = response.json() if response.headers.get('content-type') == 'application/json' else {}
                    print(f"Se rechazo correctamente con el error de validacion: {error_data}")
                elif response.status_code == 500:
                    #Error por parte del servidor (SQL invalido)
                    error_text = response.text[:200]
                    assert "syntax error" not in error_text.lower(), f"Error de sintaxis SQL: {error_text}"
                    print(f"Se rechazo correctamente con error del servidor")
                else:
                    pytest.fail(f"Respuesta no esperada para {description}: {response.status_code} - {response.text}")

            except requests.exceptions.RequestException as e:
                print(f"Petición bloqueada por un error de conexion: {e}")

    #Esta función se hace cargo de testear que solo los operadores permitidos sean aceptados
    def test_operator_validation(self, auth_token):
        invalid_operators = [
            "LIKE",
            "NOT LIKE",
            "INVALID_OP", 
            "OR",
            "AND",
            ";",
            "--",
            "/*",
            "UNION",
            "DROP",
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for operator in invalid_operators:
            print(f"\nProbando operador invalido: {operator}")
            encoded_operator = urllib.parse.quote(operator)
            url = f"{BASE_URL}/invoices?status=paid&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)
                assert response.status_code != 200, f"Operador invalido {operator} fue aceptado: {response.status_code}"

                if response.status_code == 400:
                    print(f"Operador {operator} rechazado")
                elif response.status_code == 500:
                    error_text = response.text[:200]
                    # Make sure it's not a successful injection
                    assert "UNION" not in error_text and "SELECT" not in error_text, f"Posible inyeccion con operador {operator}"
                    print(f"Operador {operator} bloqueado con error del server")

            except requests.exceptions.RequestException as e:
                print(f"Operador {operator} bloqueado por error de conexion: {e}")

    #Funcion que prueba que caracteres que podrian ser maliciosos y esten en el status sean rechazados
    def test_status_parameter_validation(self, auth_token):
        malicious_statuses = [
            "paid' OR '1'='1",
            "paid'; DROP TABLE invoices; --",
            "paid' UNION SELECT * FROM users--",
            "paid'/*",
            "paid'--",
            "paid';--",
            "paid' AND 1=1 UNION SELECT password FROM users--",
            "paid<script>alert('xss')</script>",
            "paid../../../etc/passwd",
            "paid' || (SELECT password FROM users LIMIT 1)--",
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status in malicious_statuses:
            print(f"\nProbando status malicioso: {status[:50]}...")
            encoded_status = urllib.parse.quote(status)
            url = f"{BASE_URL}/invoices?status={encoded_status}&operator=="

            try:
                response = requests.get(url, headers=headers, timeout=10)

                assert response.status_code != 200, f"Status malicioso aceptado: {status[:50]}"

                if response.status_code == 400:
                    print(f"Status malicioso rechazado: {status[:30]}...")
                elif response.status_code == 500:
                    error_text = response.text[:200]
                    assert not any(keyword in error_text.upper() for keyword in ["UNION", "SELECT", "DROP"]), f"Posible inyección exitosa con status: {status[:30]}"
                    print(f"Status malicioso bloqueado: {status[:30]}...")

            except requests.exceptions.RequestException as e:
                print(f"Status malicioso bloqueado por error de conexion: {status[:30]}...")

    #Testear que aquellas consultas que sí son legítimas sigan funcionando
    def test_legitimate_queries_still_work(self, auth_token):
        legitimate_queries = [
            ("paid", "=", "Exact status match"),
            ("unpaid", "=", "Exact status match"),
            ("pending", "=", "Exact status match"),
            ("paid", "!=", "Not equal operator"),
            ("paid", ">", "Greater than (invalid for status but tests validation)"),
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status, operator, description in legitimate_queries:
            print(f"\nProbando consulta legitima: {description} ({status} {operator})")
            encoded_status = urllib.parse.quote(status)
            encoded_operator = urllib.parse.quote(operator)

            url = f"{BASE_URL}/invoices?status={encoded_status}&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)
                if operator == ">":
                    assert response.status_code in [400, 500], f"Operador invalido, deberia ser rechazado: {operator}"
                    print(f"Operador invalido rechazado: {operator}")
                else:
                    assert response.status_code in [200, 404], f"Fallo en una consulta legitima: {response.status_code} - {response.text[:200]}"
                    print(f"Consulta legitima funcionando: {status} {operator}")

            except requests.exceptions.RequestException as e:
                if operator != ">":
                    pytest.fail(f"Consulta valida fallida por error de conexión: {e}")
                else:
                    print(f"Operador invalido bloqueado: {operator}")

    #Funcion que testea que los mensajes de error no estén mostrando o exponiendo datos sensibles
    def test_no_information_leakage(self, auth_token):
        malicious_payloads = [
            "paid' UNION SELECT table_name FROM information_schema.tables--",
            "paid' UNION SELECT column_name FROM information_schema.columns--",
            "paid'; SHOW TABLES;--",
            "paid'; SELECT database();--",
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for payload in malicious_payloads:
            encoded_payload = urllib.parse.quote(payload)
            url = f"{BASE_URL}/invoices?status={encoded_payload}&operator=="

            try:
                response = requests.get(url, headers=headers, timeout=10)

                if response.status_code == 500:
                    error_text = response.text.lower()
                    # Ensure no database information is leaked
                    assert not any(keyword in error_text for keyword in [
                        "table", "column", "database", "schema", "mysql", "postgresql"
                    ]), f"Información sensible detectada en error: {response.text[:300]}"

                    print(f"Sin información sensible en el payload: {payload[:30]}...")

            except requests.exceptions.RequestException:
                print(f"Peticion bloqueada para el payload: {payload[:30]}...")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
