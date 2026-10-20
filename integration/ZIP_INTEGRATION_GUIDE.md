# Integración del ZIP en WebGuard

## 1. Copiar el módulo

El paquete ya está ubicado en `security/webguard_scope/`. Instálalo desde la raíz del repositorio:

```bash
python -m pip install -e ./security
```

La instalación editable declara `aiohttp>=3.10,<4.0` automáticamente. El módulo requiere Python 3.11+.

## 2. Crear la autorización en el backend

El navegador del usuario **no** debe poder enviar una autorización completa para que el backend confíe en ella. El servicio debe consultar la entidad autorizada y construir `TargetAuthorization` desde datos persistidos y aprobados. Campos mínimos:

- `target_id`, `owner_id`, `grant_id`;
- `allowed_hosts`, `allowed_ports`, `allowed_path_prefixes`;
- `issued_at`, `expires_at`, `authorization_reference`;
- `isolated_lab` solo para objetivos del entorno aislado.

La autenticación y autorización de quien solicita el trabajo se verifican antes de crear `ScopeBoundHttpClient`.

## 3. Aplicar el límite servidor-side

Para tareas HTTP de backend:

```python
async with ScopeBoundHttpClient(
    grant=stored_grant,
    settings=deployment_security_settings,
    limits=job_limits,
    actor_id=authenticated_user.id,
    job_id=job.id,
    audit_sink=audit_service.write,
    # False si el grant fue revocado o modificado desde que se cargó el job.
    authorization_check=lambda: authorization_registry.is_current(stored_grant),
) as client:
    response = await client.get(url)
```

No expongas un endpoint que actúe como proxy arbitrario. La URL debe ser parte de un job autorizado que el backend ha cargado desde la base de datos, y cualquier URL derivada —incluidas redirecciones— se vuelve a validar.

## 4. Persistencia / base de datos

El módulo provee dataclasses y `AuthorizationRegistry` como interfaz de referencia. Para producción, implementa repositorios SQLAlchemy/Alembic propios del backend y conserva estos principios:

- actualizar un alcance y escribir el `AuditEvent` en la misma transacción;
- usar identificadores estables y timestamps timezone-aware en UTC;
- revocar/cancelar jobs cuando se retire una autorización; pasar `authorization_check` al cliente para denegar cada nuevo salto si el grant dejó de ser actual;
- no registrar tokens, cookies ni cuerpos sensibles;
- no confiar en la instancia `AuthorizationRegistry` al ejecutar varios workers.

## 5. Playwright, ZAP y otros motores

No basta con llamar a `validate_url()` antes de `page.goto()`. Navegación debe cubrir redirecciones, recursos secundarios, workers, WebSockets y descargas. Usa interceptación de requests y una política de red de salida a nivel de contenedor/gateway. Los motores externos deben ejecutarse en un entorno aislado con sus propios límites de red; no deben poder saltarse la frontera usando sockets directos.

## 6. Variables de entorno sugeridas

Configura en el backend y valida al arrancar:

```dotenv
WEBGUARD_ISOLATED_LAB_ENABLED=false
WEBGUARD_REQUEST_TIMEOUT_SECONDS=8
WEBGUARD_MAX_JOB_DURATION_SECONDS=60
WEBGUARD_MAX_REQUESTS_PER_JOB=40
WEBGUARD_MAX_CONCURRENCY=4
WEBGUARD_MAX_RESPONSE_BYTES=1000000
WEBGUARD_MAX_REDIRECTS=5
```

Estas variables son una convención para el dueño de configuración; la app integradora debe parsearlas y construir `SecuritySettings`/`JobLimits`. No se lee `.env` automáticamente desde este paquete.

## 7. Verificación después de integrar

```bash
python -m pip install -e ./security
cd security && ../.venv/bin/python -m pytest -q
```

Además, verifica desde el backend que el job se rechaza cuando: no existe autorización, expiró, el host/puerto/ruta no coincide, DNS responde con una IP privada, un redirect sale del alcance, se supera el presupuesto, o el usuario intenta activar el modo de laboratorio sin autorización administrativa.
