# ZIPMarkdown 0.1.0b2 — informe de preparación

Fecha: 2026-11-27

## Estado

La beta `0.1.0b2` corrige los defectos reproducibles de la revisión y se prepara como un release nuevo, sin modificar los artefactos históricos de `0.1.0b1`.

**Publicación bloqueada:** en la comprobación anónima de esta ejecución, `https://github.com/javierstampa/ZIPMarkdown` y su página de releases siguen devolviendo 404. La visibilidad del repositorio y Private Vulnerability Reporting son ajustes de GitHub que debe confirmar el propietario antes de crear el tag público `v0.1.0b2`.

## Correcciones incluidas

1. El flujo de publicación queda documentado como bloqueado mientras el repositorio no sea accesible de forma anónima.
2. Los marcadores de secretos solo se restauran en su ruta vinculada o en una recuperación única de nombre; marcadores movidos, duplicados, desconocidos o sin binding abortan antes de insertar el secreto.
3. Un fence final sin cerrar se rechaza como Markdown truncado.
4. Un manifiesto explícito de snapshot permite reconstruir carpetas y ZIP vacíos.
5. Markdown y vault comparten ID de exportación y SHA-256 del documento original; la asociación se valida y la escritura de la pareja tiene rollback.
6. Los sufijos compuestos de contraseña, secreto, clave API, tokens, clave privada y cadena de conexión se detectan con confianza alta.
7. Los artefactos de `0.1.0b2` se generan desde el commit etiquetado mediante `git archive` y `python -m build`.
8. El workflow exige coincidencia tag/versión, formato prerelease, compilación, Ruff, cobertura, pruebas, Gitleaks, pruebas Windows, checksums completos, attestation y entorno protegido `release`.
9. El README empaquetado usa una imagen absoluta fijada al tag y enlaces absolutos a la documentación del repositorio.
10. El soporte declarado es Python `>=3.10,<3.13`; Pillow y pystray pasan al extra `gui`.
11. La configuración de issues enlaza directamente con el reporte privado y se elimina la plantilla pública de seguridad.
12. La web local se excluye del árbol canónico y de los artefactos de release; no se publica como parte de `0.1.0b2`.
13. Este informe sustituye las afirmaciones contradictorias anteriores y separa claramente correcciones verificadas de ajustes externos pendientes.

## Fuente y artefactos

- Versión de paquete: `0.1.0b2`.
- Tag previsto: `v0.1.0b2`.
- `0.1.0b1` se conserva sin sobrescrituras.
- El ZIP de fuente, wheel, sdist, bundle Git y manifiesto SHA-256 se generan desde el mismo commit etiquetado.
- El ejecutable Windows debe producirlo el job Windows de GitHub Actions; no se reutiliza el EXE de `0.1.0b1`.

## Validación local

- Linux / Python 3.12: **126 pruebas superadas y 1 omitida** (`tests/windows/test_dpapi.py`, por requerir DPAPI real de Windows).
- Compilación completa con `python -m compileall -q .`: correcta.
- Round-trip instalado directamente desde el wheel: correcto, incluida la redacción y recuperación de `DJANGO_SECRET_KEY`.
- Wheel: estructura, `RECORD`, versión, `Requires-Python` y extras verificados.
- Sdist y ZIP de fuente: sin `website/` ni plantilla pública de seguridad.
- ZIP de fuente comparado byte a byte con los **51 archivos rastreados** del tag.
- Checksums SHA-256 de los cuatro artefactos de build, reunidos en el quinto adjunto `RELEASE_SHA256.txt`: verificados.
- Metadatos del workflow y referencias `uses:` fijadas a SHA de 40 caracteres: verificados.
- Ruff, cobertura instrumentada, Gitleaks, DPAPI, PyInstaller y attestation no se pudieron ejecutar en este contenedor sin sus herramientas/plataforma. Permanecen como puertas obligatorias del workflow y bloquean la publicación si fallan.

## Puertas externas pendientes

1. Hacer el repositorio visible de forma anónima.
2. Activar Private Vulnerability Reporting y comprobar, desde una sesión anónima, que aparece **Report a vulnerability**.
3. Proteger el entorno de GitHub Actions llamado `release` con las reglas de aprobación deseadas.
4. Subir el commit/tag `v0.1.0b2`; dejar que `release.yml` genere y publique los adjuntos.
5. Validar el EXE descargado de Actions en un Windows limpio y, si se dispone de certificado, añadir Authenticode.
