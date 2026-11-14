<?php
// Laboratorio intencionalmente inseguro: credenciales de alto privilegio
// (root) embebidas en la app, sin capa de permisos mínimos. Esto replica
// a propósito la debilidad #4 del PRD original (credenciales por defecto /
// permisos excesivos) para que el IDS tenga patrones reales de mala
// configuración que correlacionar, aunque aquí el motor de CENTINELA solo
// inspecciona tráfico HTTP, no configuración de base de datos.
$host = getenv('MYSQL_HOST') ?: 'gov-mysql';
$database = getenv('MYSQL_DATABASE') ?: 'tributos_db';
$password = getenv('MYSQL_ROOT_PASSWORD') ?: 'change-me-in-dev';

$conn = new mysqli($host, 'root', $password, $database);
if ($conn->connect_error) {
    die('Error de conexión: ' . $conn->connect_error);
}
