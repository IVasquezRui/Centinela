<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Plataforma de Pago de Tributos — Laboratorio CENTINELA</title>
</head>
<body>
    <h1>Sistema de Consulta de Tributos (laboratorio, datos sintéticos)</h1>
    <p>Esta aplicación es un objetivo de prueba intencionalmente vulnerable
       para la demo de CENTINELA. No contiene datos reales de contribuyentes.</p>

    <h2>Consultar deuda por cédula</h2>
    <form action="consulta.php" method="get">
        <label for="cedula">Cédula:</label>
        <input type="text" id="cedula" name="cedula" placeholder="V12345678">
        <button type="submit">Consultar</button>
    </form>

    <h2>Descargar recibo</h2>
    <form action="descargar.php" method="get">
        <label for="archivo">Nombre del recibo:</label>
        <input type="text" id="archivo" name="archivo" placeholder="recibo_0001.txt">
        <button type="submit">Descargar</button>
    </form>
</body>
</html>
