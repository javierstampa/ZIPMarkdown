# ZIP ↔ Markdown

Convierte el contenido de un ZIP en un solo `.md` y reconstruye un ZIP desde
bloques de código Markdown. Los nombres de archivo, incluidos los guiones bajos,
se conservan durante la conversión en ambos sentidos.

## Aplicación de Windows

Al abrir `ZIPMarkdown.exe`, no aparece una ventana principal: queda un icono en
el área de notificación de Windows, junto al reloj (puede estar dentro del menú
de iconos ocultos). Al hacer clic derecho aparecen únicamente estas acciones:

- **Markdown → ZIP**.
- **ZIP → Markdown**.
- **Carpeta → Markdown**.
- **Salir**.

La aplicación no revisa ni sincroniza archivos. Las conversiones se ejecutan
localmente cuando las eliges. Ejecuta `build_exe.bat` para generar
`ZIPMarkdown.exe`; el script instala PyInstaller y las dependencias del icono
de notificación si hacen falta. El EXE no requiere Python para ejecutarse.

También puedes arrastrar un `.zip` o `.md` sobre `ZIPMarkdown.exe`: se abrirá el
diálogo para elegir dónde guardar el resultado.

## Requisitos

- Python 3.10 o posterior
- Para compilar el ejecutable o extraer PDFs complejos: `pystray`, `Pillow`, `pypdf` y `PyInstaller` (instalados automáticamente con `build_exe.bat`)

## Compatibilidad con archivos PDF (Instrucciones)

Los archivos `.pdf` (como enunciados, especificaciones o guías del proyecto) son procesados automáticamente:
- **Al exportar a Markdown:** Se extrae el texto legible del PDF (página por página) y se incluye en un bloque de código para que la IA pueda leerlo directamente. El archivo PDF binario original se respalda en el vault local cifrado `.secrets`.
- **Al reconstruir a ZIP:** El archivo binario original del PDF se restaura en el ZIP sin pérdida de calidad ni formato.

## Uso

```bash
python zip_a_markdown.py proyecto.zip
```

Esto crea `proyecto.md` junto al ZIP. Ordena las rutas alfabéticamente, incluye
un índice y omite archivos binarios. Para elegir otro destino:

```bash
python zip_a_markdown.py proyecto.zip --output salida/contenido.md
```

También puedes pasar una carpeta; por defecto crea el Markdown junto a ella y
excluye automáticamente el propio archivo de salida:

```bash
python zip_a_markdown.py ruta/a/proyecto
```

Para reconstruir el ZIP desde el Markdown:

```bash
python markdown_a_zip.py salida/contenido.md
```

Cada exportación crea también un archivo cifrado `proyecto.secrets` junto al
Markdown. Al reconstruirlo con `markdown_a_zip.py`, el vault adyacente se detecta
automáticamente y se restauran los valores originales y los archivos sensibles
omitidos.

Si la IA entrega una versión nueva (y no necesariamente conserva los marcadores),
puedes aplicar el vault explícitamente a un Markdown o ZIP:

```bash
python rebase_secrets.py entrega_ia.md --secrets proyecto.secrets
python rebase_secrets.py entrega_ia.zip --secrets proyecto.secrets
```

El rebase busca primero los marcadores originales y luego asignaciones con la
misma ruta y nombre de variable cuyo valor sea un marcador o placeholder. No
reemplaza valores reales distintos. Las coincidencias ausentes o ambiguas se
informan, pero no impiden crear el ZIP; los archivos sensibles originales que
falten se añaden desde el vault.

El extractor obtiene las rutas de los encabezados, preferiblemente en formato
de código en línea (por ejemplo, ``## `Cuantica/caq_gemv_v5.cu` ``), y conserva
los `_` literales para que los nombres reconstruidos no pierdan caracteres.
Si un encabezado ya perdió separadores, también puede recuperar el nombre
cuando otro archivo contiene un `#include` inequívoco; los casos ambiguos no se
modifican.

El programa informa cuántos archivos de texto incluyó y cuántos binarios
omitió. También admite textos UTF-8, UTF-16 y Windows-1252.

## Protección de secretos al exportar a Markdown

Al convertir un ZIP o una carpeta a Markdown, se omiten rutas y archivos
habitualmente sensibles (por ejemplo, `.env` reales, `.aws`, `.ssh`, archivos de
credenciales y claves privadas), además de carpetas de dependencias y artefactos
como `node_modules`, `.venv`, `venv`, `build`, `dist`, `target` y cachés. Las
plantillas `.env.example`, `.env.sample`, `.env.template` y `.env.dist` sí se
incluyen para ayudar a configurar el sandbox. También
se redactan valores reconocibles de contraseñas, tokens, claves API, cadenas de
conexión y claves privadas. El Markdown generado y el diálogo de finalización
muestran los recuentos de archivos omitidos y valores redactados.

La detección es una defensa adicional, no una garantía: formatos propietarios,
valores codificados u otros nombres de credenciales pueden no reconocerse.
Antes de enviar el Markdown a una IA, revisa el archivo generado y no incluyas
secretos reales en ejemplos o documentación que deban conservarse literalmente.

La redacción conserva las líneas de código y sustituye cada secreto detectado
por un marcador reversible. El `.secrets` contiene los valores y archivos
sensibles originales cifrados mediante DPAPI de Windows: solo se puede abrir con
la misma cuenta de Windows. Guárdalo en local y **no lo envíes a la IA**. Si
pierdes el vault, los valores omitidos no se pueden recuperar.

El Markdown sirve como contexto para reconstruir la aplicación, pero no incluye
binarios, dependencias vendorizadas ni artefactos; el vault tampoco es una copia
completa del proyecto. Las dependencias se pueden reconstruir si sus manifiestos
(por ejemplo `requirements.txt` o `package.json`) están incluidos. La detección
de secretos no es infalible: revisa siempre el Markdown antes de compartirlo.
