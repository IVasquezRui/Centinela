-- CENTINELA — seed de ~15 técnicas MITRE ATT&CK y catálogo inicial de reglas.
-- El catálogo vivo de reglas que evalúa el motor es app/engine/rules.yaml;
-- esta copia en SQL existe para que `rule.technique_id` tenga FK válida y
-- para que /api/events pueda hacer join con el nombre/táctica ATT&CK.

INSERT INTO attack_technique (technique_id, name, tactic, description) VALUES
    ('T1190',     'Exploit Public-Facing Application',  'Initial Access',      'Explotación de una aplicación expuesta a internet, p. ej. mediante inyección SQL.'),
    ('T1059',     'Command and Scripting Interpreter',  'Execution',           'Ejecución de comandos del sistema operativo a través de un intérprete de comandos.'),
    ('T1059.007', 'JavaScript',                          'Execution',           'Ejecución de JavaScript malicioso, típicamente vía Cross-Site Scripting (XSS).'),
    ('T1083',     'File and Directory Discovery',        'Discovery',           'Enumeración o lectura de archivos y directorios no autorizados (path traversal / LFI).'),
    ('T1595',     'Active Scanning',                     'Reconnaissance',      'Escaneo activo de un objetivo para identificar vulnerabilidades explotables.'),
    ('T1595.002', 'Vulnerability Scanning',               'Reconnaissance',      'Escaneo automatizado de rutas y configuraciones conocidas en busca de debilidades.'),
    ('T1110',     'Brute Force',                          'Credential Access',   'Intentos repetidos de adivinar credenciales válidas.'),
    ('T1071',     'Application Layer Protocol',           'Command and Control', 'Uso de protocolos de capa de aplicación (HTTP/HTTPS) para comunicación C2.'),
    ('T1041',     'Exfiltration Over C2 Channel',         'Exfiltration',        'Extracción de datos a través del mismo canal usado para el control del ataque.'),
    ('T1486',     'Data Encrypted for Impact',            'Impact',              'Cifrado malicioso de datos con fines de extorsión (ransomware).'),
    ('T1046',     'Network Service Discovery',            'Discovery',           'Identificación de servicios de red activos y sus versiones.'),
    ('T1078',     'Valid Accounts',                       'Initial Access',      'Uso de credenciales legítimas obtenidas de forma ilegítima.'),
    ('T1505.003', 'Web Shell',                             'Persistence',         'Instalación de una interfaz de control remoto sobre un servidor web comprometido.'),
    ('T1557',     'Adversary-in-the-Middle',               'Collection',          'Interceptación de tráfico entre dos partes para robo o manipulación de datos.'),
    ('T1498',     'Network Denial of Service',             'Impact',              'Saturación de un servicio de red para degradar o interrumpir su disponibilidad.')
ON CONFLICT (technique_id) DO NOTHING;

-- Copia del catálogo inicial de app/engine/rules.yaml (mantener sincronizado
-- a mano durante el Sprint 1; automatizar la carga desde YAML es Sprint 2+).
-- La última fila NO es una regla del motor: es la acción de RESPUESTA que emite
-- el IPS (app/ips/blocklist.py) cuando una IP supera el umbral de bloqueos. Se
-- siembra aquí porque event.rule_id tiene FK contra rule(id) y, sin esta fila,
-- cada evento de cuarentena rompía la transacción y se perdía evidencia.
INSERT INTO rule (id, category, severity, technique_id, description, pattern) VALUES
    ('CNT-SQLI-001',      'sqli',       'critica', 'T1190',     'Tautología clásica de SQL injection ('' OR ''1''=''1)', '(?i)(''|%27)?\s*(or|and)\s+(''?[a-z0-9_$]+''?\s*=\s*''?[a-z0-9_$]+''?|\(\s*select\b|\btrue\b|\bfalse\b)'),
    ('CNT-SQLI-002',      'sqli',       'critica', 'T1190',     'UNION SELECT típico de extracción de datos vía SQLi', '(?i)union\s+((all|distinct)\s+)?select'),
    ('CNT-SQLI-003',      'sqli',       'alta',    'T1190',     'Comentario SQL para truncar la consulta original (-- o #)', '(?i)(--\s*$|--\s+|#\s*$|/\*.*?\*/)'),
    ('CNT-SQLI-004',      'sqli',       'alta',    'T1190',     'Funciones de retardo usadas para SQLi a ciegas (SLEEP/BENCHMARK)', '(?i)(\b(sleep|benchmark|pg_sleep)\b|waitfor\s+delay)'),
    ('CNT-SQLI-005',      'sqli',       'alta',    'T1190',     'Comandos destructivos o de manipulación DDL/DML en inyección SQL', '(?i)(;\s*)?(drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b'),
    ('CNT-XSS-001',       'xss',        'alta',    'T1059.007', 'Etiqueta <script> inyectada en parámetros o cuerpo', '(?i)<script[^>]*>'),
    ('CNT-XSS-002',       'xss',        'media',   'T1059.007', 'Manejador de evento inline típico de XSS (onerror=, onload=)', '(?i)on(error|load|click|mouseover)\s*='),
    ('CNT-XSS-003',       'xss',        'media',   'T1059.007', 'Esquema javascript: usado para ejecutar script desde un atributo', '(?i)javascript\s*:'),
    ('CNT-XSS-004',       'xss',        'alta',    'T1059.007', 'Inyección de elementos DOM para XSS (svg, iframe, img, body)', '(?i)<(iframe|svg|body|object|embed|style|meta)\b[^>]*>'),
    ('CNT-TRAVERSAL-001', 'traversal',  'critica', 'T1083',     'Secuencia ../ para escapar del directorio base (path traversal / LFI)', '(\.\./|\.\.%2f|%2e%2e/){2,}'),
    ('CNT-TRAVERSAL-002', 'traversal',  'alta',    'T1083',     'Lectura directa de archivos sensibles del sistema', '(?i)(etc/passwd|boot\.ini|win\.ini|proc/self/environ)'),
    ('CNT-TRAVERSAL-003', 'traversal',  'alta',    'T1083',     'Inclusión de archivos mediante esquemas de wrapper (php://, file://, data://)', '(?i)(php|file|data|zip|phar)://'),
    ('CNT-CMDI-001',      'cmdi',       'critica', 'T1059',     'Encadenado de comandos de shell (;, |, &&) junto a binarios típicos', '(?i)(;|\||&&)\s*(cat|ls|whoami|id|curl|wget|nc|bash|sh|echo|printf|python3?|perl|ruby|node|php|touch|rm|cp|mv|grep|sed|awk|env|printenv)\b'),
    ('CNT-CMDI-002',      'cmdi',       'alta',    'T1059',     'Sustitución de comandos vía backticks o $()', '`[^`]+`|\$\([^)]+\)'),
    ('CNT-CMDI-003',      'cmdi',       'critica', 'T1059',     'Pipes a intérpretes de comandos o redirección de descriptores de red', '(?i)(\|\s*(bash|sh|zsh|dash)|>\s*/dev/(tcp|udp)|nc\s+-[el])\b'),
    ('CNT-SCANNER-001',   'scanner',    'baja',    'T1595',     'User-Agent de herramientas automatizadas de escaneo', '(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus)'),
    ('CNT-SCANNER-002',   'scanner',    'media',   'T1595.002', 'Sondeo de rutas administrativas o de configuración comunes', '(?i)/(\.git/|\.env|wp-admin|phpmyadmin|admin/config)'),
    ('CNT-SCANNER-003',   'scanner',    'media',   'T1595.002', 'Sondeo de copias de seguridad, archivos temporales o volcados sensibles', '(?i)\.(bak|old|backup|sql|tar\.gz|zip|swp|temp)(~|\b)'),
    ('CNT-BRUTEFORCE-001','bruteforce', 'media',   'T1110',     'Intento de acceso a endpoint de login con credenciales por defecto', '(?i)(username|usuario)=admin[^=]{0,64}(password|clave)=(admin|123456|root)'),
    ('CNT-BRUTEFORCE-002','bruteforce', 'media',   'T1110',     'Intento masivo o patrón de diccionario en parámetros de clave', '(?i)(pass(word)?|pin|secret|token)=(''''|"|%27)?(1234|password|qwerty|toor|admin123|guest)\b'),
    -- Fila de RESPUESTA del IPS (no es una regla del motor, ver nota arriba):
    -- sin ella, cada evento de cuarentena rompía la FK event.rule_id -> rule.id.
    ('CNT-IPS-QUARANTINE', 'ips',       'alta',    'T1110',     'IP en cuarentena por el IPS tras superar el umbral de detecciones (403 inmediato sin reevaluar reglas)', '(?!)'),
    ('CNT-ENGINE-BUDGET',  'ips',       'alta',    'T1498',     'Presupuesto de tiempo de una regla excedido: bloqueo preventivo (fail-closed) contra ReDoS', '(?!)'),
    ('CNT-BODY-TOO-LARGE', 'ips',       'media',   'T1498',     'Cuerpo de peticion por encima del limite permitido (413)', '(?!)')
ON CONFLICT (id) DO NOTHING;
