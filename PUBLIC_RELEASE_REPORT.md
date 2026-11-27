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

- Versión Python PEP 440: `0.1.0b1`; etiqueta prevista: `v0.1.0-beta`.
- Wheel y sdist regenerados con los nuevos módulos de seguridad incluidos.
- Web y metadatos muestran `0.1.0b1`.
- Las URLs públicas permanecen sin inventar por decisión expresa: no existe todavía un remoto ni repositorio público verificable. Deben añadirse a `pyproject.toml` y `website/src/content/product.ts` cuando se cree el destino real.
- Informe y checksums se regeneraron desde este árbol.

## Validación ejecutada

- Python (Windows · Python 3.14): **112 pruebas superadas; 2 omitidas** (fixtures POSIX de colisión por mayúsculas y symlink), incluyendo `tests/windows/test_dpapi.py` (DPAPI real).
- Suite portable + cobertura branch-aware (`tests/unit` + `tests/integration`): **111 superadas, 2 omitidas, 84.13% de cobertura** (supera el mínimo de 80%).
- `ruff check .`: superado sin errores.
- Compilación de todos los módulos Python (`python -m compileall -q .`): correcta.
- Wheel `zipmarkdown-0.1.0b1-py3-none-any.whl` y sdist `zipmarkdown-0.1.0b1.tar.gz`: construidas mediante `setuptools.build_meta` y verificadas (`path_safety.py` y `secret_scanner.py` incluidos).
- Workflows: todas las referencias `uses:` verificadas como SHA de 40 caracteres; job web retirado del repo al mantenerse la web únicamente en local.
- Lockfile: estructura y versiones fijadas verificadas.

## Limitaciones de esta ejecución

- El entorno local sin conexión en el sandbox no dispone de `gitleaks` en `PATH`, por lo que ese escaneo queda pendiente de ejecutarse en GitHub Actions.
- La puerta de Gitleaks queda configurada como fallo obligatorio de CI y debe ejecutarse en GitHub antes de publicar.
- Siguen pendientes GUI/EXE, checksum del EXE y prueba en Windows limpio.
- Al publicar el repositorio, falta habilitar/verificar Private Vulnerability Reporting.

## Puertas finales de publicación

1. Verificar URLs del repositorio (`https://github.com/javierstampa/ZIPMarkdown`) y visibilidad pública cuando corresponda.
2. Habilitar Private Vulnerability Reporting.
3. Ejecutar CI alojada completa sin excepciones en Linux y Windows.
4. Validar DPAPI, GUI y EXE en Windows limpio y publicar el checksum real del EXE.
5. Publicar `v0.1.0-beta` solo si las cuatro puertas anteriores pasan.
