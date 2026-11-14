<?php
// VULNERABILIDAD INTENCIONAL #2: Local File Inclusion / path traversal.
// `archivo` se concatena directamente a la ruta base sin basename() ni
// validación de extensión, permitiendo escapar con ../ hacia cualquier
// archivo legible por el proceso de Apache. Objetivo de laboratorio para
// que CENTINELA demuestre la detección de la regla CNT-TRAVERSAL-00x.
header('Content-Type: text/plain; charset=utf-8');

$baseDir = __DIR__ . '/recibos/';
$archivo = $_GET['archivo'] ?? '';

// Vulnerable a propósito: NO usar basename()/realpath() con validación de
// prefijo aquí. No replicar este patrón fuera de este laboratorio.
$ruta = $baseDir . $archivo;

if (!file_exists($ruta)) {
    http_response_code(404);
    echo "Archivo no encontrado: $archivo\n";
    exit;
}

readfile($ruta);
