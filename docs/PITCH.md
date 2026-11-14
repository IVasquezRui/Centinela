# Guion Oficial del Pitch y Demostración en Vivo (3 Minutos) — CENTINELA

> **Hackathon:** UNETI IA 2026 · Eje Ciberseguridad  
> **Proyecto:** CENTINELA (Unificación Proyectos #23 y #40)  
> **Metodología:** Specification-Driven Development (SDD)  
> **Tiempo Límite:** 3:00 minutos (180 segundos) · Sin prórroga  
> **Presentador / Voz Principal:** José Estanga (Documentación)  
> **Operador Técnico / Terminal:** Karla (DevOps)  
> **Soporte de Arquitectura y Respuestas:** Iván (Motor/Gateway), Rafael/José Oropeza (Frontend/ML), Luis (Datos/Integración)

---

## ⏱️ Estructura Cronometrada Segundo a Segundo

```mermaid
timeline
    title Minutaje del Pitch de CENTINELA (Total: 180s)
    00:00 - 00:30 : El Problema y la Tesis (30s)
    00:30 - 01:15 : Simulación en Vivo e IPS (45s)
    01:15 - 01:50 : Inspección Forense y Copiloto IA (35s)
    01:50 - 02:20 : Momento de Impacto - Auditoría Rota (30s)
    02:20 - 02:50 : Observatorio Ciudadano (30s)
    02:50 - 03:00 : Cierre y Métricas Finales (10s)
```

---

### Acto 1: El Problema y la Tesis (0:00 – 0:30) · [30 segundos]
* **Pantalla visible:** Navegador en `http://localhost:5173` (Panel SOC de CENTINELA vacío, KPIs en cero, modo oscuro, estado de servicios en verde).
* **Quién actúa:** José Estanga habla con voz firme y clara.

> **[José Estanga]:**  
> *"Buenos días, miembros del jurado. En las instituciones públicas de Venezuela, los portales web y plataformas de trámites sufren escaneos, inyecciones de código y ataques de denegación de servicio a diario. Los equipos de TI se ahogan en gigabytes de logs inmanejables, mientras que los ciudadanos y decisores navegan a ciegas, sin saber qué amenazas nos amenazan.*
>
> *Para resolver esta doble fractura creamos **CENTINELA**, unificando la detección operativa y la divulgación nacional bajo una sola tesis:*  
> **'CENTINELA detecta, bloquea y audita en el ente; agrega, anonimiza y publica en el país.'**"

---

### Acto 2: Inyección de Tráfico y Respuesta IPS (0:30 – 1:15) · [45 segundos]
* **Pantalla visible:** Split-screen o transición rápida: Terminal de Karla a un lado y Panel SOC al otro.
* **Quién actúa:** Karla ejecuta el comando en la terminal. José relata la acción.

* **Comando que ejecuta Karla:**
  ```bash
  # Windows PowerShell:
  .\scripts\demo.ps1
  # O en Linux / Makefile:
  make demo
  ```
  *(Simulador inyecta 1.000 peticiones mixtas: 70% legítimas a trámites y 30% vectores maliciosos de SQLi, XSS, Path Traversal y Command Injection).*

> **[José Estanga]:**  
> *"En este instante, Karla lanza nuestro simulador: 1.000 peticiones mixtas dirigidas a dos aplicaciones gubernamentales de laboratorio aisladas.*
>
> *Observen la pantalla del SOC: gracias a **Server-Sent Events (SSE)**, la telemetría fluye en tiempo real sin recargar la página. El tráfico legítimo fluye sin fricción hacia los servicios internos con HTTP 200. Pero los ataques son interceptados en el borde por nuestro gateway inline:*
> * *Tiempo de CPU del motor:* **menos de 2 milisegundos por petición**.
> * *Respuesta inmediata:* **HTTP 403 Forbidden**. El paquete malicioso jamás toca los servidores vulnerables.*
> * *Modo IPS activado:* Al registrar 3 ataques en 60 segundos, la dirección IP del atacante es enviada automáticamente a **cuarentena por 5 minutos**, neutralizando ráfagas posteriores sin consumir cómputo de inspección.*"

---

### Acto 3: Inspección Forense y Copiloto IA (1:15 – 1:50) · [35 segundos]
* **Pantalla visible:** José pide a Karla hacer clic en una alerta bloqueada en la tabla (ej. `CNT-SQLI-001` o `CNT-TRAV-001`). Se despliega el panel de detalle lateral/modal.
* **Quién actúa:** José Estanga señala los campos en pantalla.

> **[José Estanga]:**  
> *"Al inspeccionar cualquier incidente bloqueado, vemos trazabilidad total: la regla exacta disparada, su correlación con la matriz **MITRE ATT&CK (`T1190`)**, y la puntuación de anomalía de nuestro modelo de Machine Learning (`ml_score`).*
>
> *Y aquí interviene nuestro **Copiloto de IA**, potenciado por DeepSeek: la IA analiza el payload sanitizado (sin datos personales) y redacta en español claro el resumen forense y la recomendación de mitigación.*
>
> *Queremos resaltar un principio ético no negociable de CENTINELA:*  
> **La Inteligencia Artificial explica y asiste, pero NUNCA tiene autoridad para bloquear.** *El veredicto es 100% determinista. Si la IA o la red fallan, CENTINELA activa su plantilla determinista de respaldo en menos de 3 segundos y la seguridad del Estado jamás se interrumpe.*"

---

### Acto 4: El Momento de Impacto — Integridad de Auditoría (1:50 – 2:20) · [30 segundos]
* **Pantalla visible:** Terminal de Karla ejecutando el ataque de manipulación interna, seguida por el Panel SOC con el botón *"Verificar auditoría"*.
* **Quién actúa:** Karla ejecuta el script de rotura; José narra el clímax técnico.

* **Comando que ejecuta Karla:**
  ```bash
  python scripts/demo_momento_impacto.py
  ```
  *(Altera deliberadamente un campo en la tabla `audit_log` simulando a un atacante con acceso a la BD intentando borrar sus huellas).*

> **[José Estanga]:**  
> *"Un IDS que no puede probar la inmutabilidad de sus registros no sirve ante un tribunal o una auditoría de la Contraloría. ¿Qué pasa si un atacante o un administrador corrupto intenta alterar un log en la base de datos?*
>
> *Karla acaba de modificar directamente una fila en PostgreSQL. Ahora pulsamos en vivo el botón **'Verificar auditoría'**.*
>
> *(Aparece la alerta roja en la interfaz)*
>
> *¡El sistema detecta la alteración al instante! Cada registro está encadenado criptográficamente con hashes **SHA-256 (`hash_anterior + contenido`)**. CENTINELA nos dice: **Cadena rota en el registro ID #3**. La evidencia no fue silenciada. Además, los permisos de base de datos revocan `UPDATE` y `DELETE` al rol de la aplicación en producción.*"

---

### Acto 5: Observatorio Nacional Ciudadano y Cierre (2:20 – 3:00) · [40 segundos]
* **Pantalla visible:** Navegador cambia a la pestaña `http://localhost:5173/publico` (Observatorio Nacional).
* **Quién actúa:** José Estanga concluye con el impacto social y las métricas finales.

> **[José Estanga]:**  
> *"Finalmente, pasamos a la segunda cara de la plataforma: el **Observatorio Nacional de Ciberseguridad**.*
>
> *Sin que ningún analista tenga que cargar datos a mano en Excel, los mismos ataques bloqueados en los entes se anonimizan, se agrupan y se publican automáticamente para toda la ciudadanía: 5 indicadores macro en tiempo real, mapa de severidad y alertas en lenguaje simple y accesible.*
>
> *En resumen:*
> 1. **Latencia p95 real:** *1.8 milisegundos*.
> 2. **Detección:** *100% de ataques del corpus bloqueados*.
> 3. **Falsos positivos:** *0% en el motor en línea*.
> 4. **Respaldo:** *Auditoría matemática demostrable.*
>
> *CENTINELA protege las instituciones hoy y educa a la nación para el mañana.*  
> *Muchas gracias, jurado. Quedamos atentos a sus preguntas.*"

---

## 🛡️ Plan de Contingencia en Vivo (Si algo falla)

| Escenario de Falla | Plan de Contingencia Inmediato |
|---|---|
| **La API de DeepSeek no responde o hay latencia:** | No detenerse. Mostrar que el evento tiene el prefijo `[fallback_template]`. Explicar al jurado: *"Esto demuestra en vivo la resiliencia del sistema: ante la caída del proveedor de IA, la plantilla de respaldo garantizó la continuidad del servicio."* |
| **El simulador tarda más de lo previsto:** | Karla lanza el comando con `--total 300` en vez de `1000` para una ráfaga más rápida de 10 segundos. |
| **Falla la pantalla o el proyector:** | Abrir la carpeta `docs/screenshots/` donde están respaldadas las capturas en alta definición de cada paso de la demo. |
| **Se requiere reiniciar todo el stack a cero:** | Ejecutar `make reset-db` o `.\scripts\reset-db.ps1`. En **6.6 segundos**, la base de datos se trunca, el IPS se reinicia y la cadena vuelve a `GENESIS` limpia. |

---

## 🧠 Banco de Respuestas a Preguntas Difíciles del Jurado

### 1. "¿Por qué usan reglas deterministas en vez de dejar que el Machine Learning decida el bloqueo?"
> **Respuesta (Iván / José):**  
> *"En infraestructuras críticas del Estado, un falso positivo puede suspender un servicio vital (como un portal tributario o de salud). El motor determinista garantiza una latencia fija menor a 2 ms, cero falsos positivos en peticiones legítimas y una vinculación jurídica exacta con MITRE ATT&CK. El Machine Learning y la IA son analistas excepcionales, pero en el borde de la red la decisión debe ser rápida, determinista y explicable."*

### 2. "Vimos en su documentación que el F1-Score del ML dio 0.7460 y no el 0.90 del SDD #23. ¿Por qué?"
> **Respuesta (José Oropeza / José Estanga):**  
> *"Así es, y lo documentamos con total transparencia en `docs/metricas.md`. El dataset oficial NSL-KDD en su split de prueba `KDDTest+` introduce 17 tipos de ataques nuevos que no existen en el entrenamiento (ataques de día cero como U2R y R2L). Logramos una precisión de 96.58% y una tasa de falsos positivos de apenas 2.84%. Como la metodología SDD exige compuertas de control, activamos de inmediato el **Plan B de la compuerta F3**: el motor determinista asume la vanguardia del bloqueo y el ML opera como señal enriquecedora fuera del camino crítico."*

### 3. "¿Cómo evitan que un atacante engañe a la IA mediante Prompt Injection en el payload HTTP?"
> **Respuesta (Luis / Iván):**  
> *"Implementamos tres barreras en `app/ai/sanitizer.py`: primero, el payload es saneado eliminando PII y patrones de inyección de instrucciones (como 'Ignore previous instructions'); segundo, el prompt del sistema usa delimitadores estrictos; y tercero, la salida del LLM se valida contra un esquema JSON estricto (`Pydantic`). Si el JSON no cumple el esquema, se descarta y entra la plantilla determinista."*

### 4. "¿Por qué Docker Compose local y no Kubernetes o servicios en la nube?"
> **Respuesta (Karla):**  
> *"Por soberanía tecnológica y reproducibilidad estricta. Muchas redes gubernamentales operan en entornos aislados o air-gapped sin acceso a nubes foráneas. Un stack Docker Compose autocontenido permite desplegar CENTINELA en cualquier servidor institucional en minutos, sin costos de suscripción ni dependencia de cuotas de terceros."*

---

*Guion elaborado y verificado para la presentación final por **José Estanga** (Documentación).*
