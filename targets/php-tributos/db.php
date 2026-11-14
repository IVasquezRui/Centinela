<?php
// Laboratorio intencionalmente inseguro: credenciales de alto privilegio
// (root) embebidas en la app, sin capa de permisos mínimos. Esto replica
// a propósito la debilidad #4 del PRD original (credenciales por defecto /
// permisos excesivos) para que el IDS tenga patrones reales de mala
// configuración que correlacionar, aunque aquí el motor de CENTINELA solo
// inspecciona tráfico HTTP, no configuración de base de datos.
$host = getenv('MYSQL_HOST') ?: 'gov-mysql';
$database = getenv('MYSQL_DATABASE') ?: 'tributos_db';

// La contraseña de root ya no se pasa en claro por variable de entorno (visible
// en `docker inspect`): llega como secreto de Docker y se lee del archivo.
$passwordFile = getenv('MYSQL_ROOT_PASSWORD_FILE') ?: '';
$password = '';
if ($passwordFile !== '' && is_readable($passwordFile)) {
    $password = trim((string) file_get_contents($passwordFile));
}
if ($password === '') {
    // Compatibilidad con ejecución local fuera de docker-compose.
    $password = getenv('MYSQL_ROOT_PASSWORD') ?: '';
}

$conn = new mysqli($host, 'root', $password, $database);
if ($conn->connect_error) {
    die('Error de conexión: ' . $conn->connect_error);
}
