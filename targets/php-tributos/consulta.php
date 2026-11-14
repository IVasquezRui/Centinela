<?php
// VULNERABILIDAD INTENCIONAL #1: SQL injection clásico.
// `cedula` se concatena directamente en la consulta, sin prepared
// statements ni escape. Objetivo de laboratorio para que CENTINELA
// demuestre la detección de la regla CNT-SQLI-00x en vivo.
require __DIR__ . '/db.php';

header('Content-Type: text/plain; charset=utf-8');

$cedula = $_GET['cedula'] ?? '';

// Vulnerable a propósito: NO usar mysqli_real_escape_string ni prepared
// statements aquí. No replicar este patrón fuera de este laboratorio.
$query = "SELECT cedula, nombre, monto_adeudado, periodo FROM contribuyentes WHERE cedula = '$cedula'";

$result = $conn->query($query);

if ($result === false) {
    echo "Error en la consulta.\n";
    exit;
}

if ($result->num_rows === 0) {
    echo "Sin resultados para la cédula indicada.\n";
    exit;
}

while ($row = $result->fetch_assoc()) {
    printf(
        "Cédula: %s | Nombre: %s | Monto adeudado: %s | Periodo: %s\n",
        $row['cedula'],
        $row['nombre'],
        $row['monto_adeudado'],
        $row['periodo']
    );
}
