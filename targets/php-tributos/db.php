<?php
// Laboratorio intencionalmente inseguro: la app se conecta con una cuenta
// de credenciales débiles y permisos excesivos (GRANT ALL sobre toda la
// base de datos, cuando solo necesita SELECT), sin capa de permisos
// mínimos. Esto replica a propósito la debilidad #4 del PRD original
// (credenciales por defecto / permisos excesivos) para que el IDS tenga
// patrones reales de mala configuración que correlacionar, aunque aquí el
// motor de CENTINELA solo inspecciona tráfico HTTP, no configuración de
// base de datos.
//
// Nota técnica: originalmente esta app se conectaba como "root"; se cambió
// a un usuario de aplicación dedicado ("gov_app") por buena práctica — la
// "credencial débil y permisos excesivos" (GRANT ALL, cuando solo hace
// falta SELECT) sigue intacta, solo ya no es literalmente "root".
//
// Durante el desarrollo esto pareció un bug de la imagen mysql:5.7 (cuentas
// creadas en el arranque "no autenticaban en remoto"), pero la causa real
// era otra: scripts/gen-secrets.sh generaba los secretos con un \r final
// (CRLF) al correr `openssl` vía Git Bash en Windows. El bootstrap de MySQL
// lee ese archivo por shell (que solo recorta \n, no \r) y arma la cuenta
// con la contraseña "...\r" incluida; PHP, en cambio, usa trim() más abajo,
// que SÍ recorta el \r. Dos lecturas del mismo archivo, dos contraseñas
// distintas — por eso la cuenta nunca autenticaba desde PHP aunque el hash
// estuviera "bien". Arreglado en gen-secrets.sh (ver ese archivo); si algún
// secreto viejo quedó con el \r, hay que regenerarlo y recrear el volumen
// de MySQL (los datos son sintéticos, no hay nada que preservar).
$host = getenv('MYSQL_HOST') ?: 'gov-mysql';
$database = getenv('MYSQL_DATABASE') ?: 'tributos_db';
$user = getenv('GOV_APP_USER') ?: 'gov_app';

// La contraseña ya no se pasa en claro por variable de entorno (visible en
// `docker inspect`): llega como secreto de Docker y se lee del archivo.
$passwordFile = getenv('GOV_APP_PASSWORD_FILE') ?: '';
$password = '';
if ($passwordFile !== '' && is_readable($passwordFile)) {
    $password = trim((string) file_get_contents($passwordFile));
}
if ($password === '') {
    // Compatibilidad con ejecución local fuera de docker-compose.
    $password = getenv('GOV_APP_PASSWORD') ?: '';
}

$conn = new mysqli($host, $user, $password, $database);
if ($conn->connect_error) {
    die('Error de conexión: ' . $conn->connect_error);
}
