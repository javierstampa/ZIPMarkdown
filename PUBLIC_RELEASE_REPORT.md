# ZIPMarkdown 0.1.0b1 — informe de preparación comunitaria

Fecha de regeneración: 2026-11-27

## Veredicto

El árbol canónico está preparado como candidato técnico de primera beta comunitaria. Se corrigieron los bloqueantes reproducibles de pérdida de datos, detección de secretos, importación no acotada, colisión de mensaje duplicado en `archive_safety.py` y cobertura Python branch-aware por encima del 80%. La publicación pública sigue condicionada a las puertas de infraestructura: configurar/verificar el repositorio público, habilitar Private Vulnerability Reporting cuando sea público, ejecutar la CI alojada y validar GUI/EXE en Windows limpio.

## Fuente canónica y limpieza

- La raíz de `Md` es la única fuente editable; los ZIP históricos no son fuente de verdad.
- Se consolidó el candidato final en la raíz y se eliminaron cachés, `build/`, `dist/`, `*.egg-info`, artefactos históricos e informes/checksums obsoletos.
- El ZIP de fuente `ZIPMarkdown-0.1.0b1-source.zip` es un artefacto derivado y reproducible, no una segunda copia editable.

## Correcciones de seguridad y datos

- Entrada, salida, vault y sidecar pasan por una identidad de ruta conservadora (resolución, Unicode NFC y comparación sin distinguir mayúsculas).
- Exportar exige `.md`; reconstruir y rebasar exigen `.zip`; `.secrets` queda reservado para vaults.
- Las cuatro colisiones destructivas de import, export, sidecar/vault y rebase quedan rechazadas antes de escribir y tienen regresiones que verifican que el archivo protegido no cambia.
- `password = "Winter26!"` y `Authorization: Bearer abcdefghijklmnopqrstuvwxyz` ya se redactan de forma reversible.
- `--strict-secrets` detiene hallazgos ambiguos y exige un escaneo limpio de Gitleaks sobre el Markdown generado antes de escribir Markdown o vault.
- El importador comprueba el tamaño físico del Markdown antes de abrirlo y lo procesa incrementalmente, cortando por bytes de entrada, longitud de línea/bloque, número de bloques, tamaño por archivo y total reconstruido.

## CI y web reproducibles

- TypeScript y `@playwright/test` están declarados con versiones exactas.
- `package-lock.json` lockfile v3 está incluido; CI usa `npm ci`.
- Playwright Chromium E2E forma parte de CI después del build.
- Todas las acciones de GitHub están fijadas a SHA completo de 40 caracteres.
- La allowlist de Gitleaks ya no excluye toda la carpeta de pruebas; solo admite patrones sintéticos explícitos.
- CI exige cobertura Python branch-aware mínima del 80%.

## Empaquetado y comunicación

- Versión Python PEP 440: `0.1.0b1`; etiqueta prevista: `v0.1.0b1` (workflow `release.yml` con trigger `v*`).
- Wheel y sdist verificados con los nuevos módulos de seguridad incluidos.
- URLs reales (`https://github.com/javierstampa/ZIPMarkdown`) añadidas a `pyproject.toml`.
- Informe regenerado desde este árbol.

## Validación ejecutada

- Python (Windows · Python 3.14): **112 pruebas superadas; 2 omitidas** (fixtures POSIX de colisión por mayúsculas y symlink), incluyendo `tests/windows/test_dpapi.py` (DPAPI real).
- Suite portable + cobertura branch-aware (`tests/unit` + `tests/integration`): **111 superadas, 2 omitidas, 84.13% de cobertura** (supera el mínimo de 80%).
- `ruff check .`: superado sin errores.
- Compilación de todos los módulos Python (`python -m compileall -q .`): correcta.
- Wheel `zipmarkdown-0.1.0b1-py3-none-any.whl` y sdist `zipmarkdown-0.1.0b1.tar.gz`: construidas mediante `setuptools.build_meta` y verificadas (`path_safety.py` y `secret_scanner.py` incluidos).
- Ejecutable local `dist\ZIPMarkdown.exe` (`42,422,371` bytes) y `dist\ZIPMarkdown.exe.sha256`: compilados localmente con PyInstaller; prueba manual en sesión gráfica/Windows limpio pendiente.
- Workflows: todas las referencias `uses:` verificadas como SHA de 40 caracteres; job web retirado del repo al mantenerse la web únicamente en local; `release.yml` configurado con trigger `v*` y artefactos dinámicos.

## Limitaciones de esta ejecución

- El entorno local sin conexión en el sandbox no dispone de `gitleaks` en `PATH`, por lo que ese escaneo sobre todo el historial queda pendiente de ejecutarse en GitHub Actions.
- La puerta de Gitleaks queda configurada como fallo obligatorio de CI y debe pasar en verde en GitHub antes de hacer público el repositorio.
- Siguen pendientes el smoke test de GUI/EXE descargado desde Actions y la prueba en Windows limpio.
- Al hacer público el repositorio, falta activar Private Vulnerability Reporting y actualizar el TODO de `SECURITY.md` con el enlace real.

## Puertas finales de publicación

1. Verificar los jobs en verde en GitHub Actions (`portable`, `windows` y `secret-scan` con `fetch-depth: 0`).
2. Probar el `ZIPMarkdown.exe` generado por Actions en Windows limpio.
3. Pasar el repositorio a público, activar Private Vulnerability Reporting y sustituir el TODO en `SECURITY.md`.
4. Publicar el tag `v0.1.0b1` solo si las puertas anteriores pasan.
