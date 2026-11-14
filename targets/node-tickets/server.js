// Objetivo de laboratorio DELIBERADAMENTE vulnerable. Dos fallos clásicos
// a propósito, para que CENTINELA tenga tráfico de ataque real que
// detectar y bloquear en la demo. No replicar estos patrones fuera de
// este laboratorio aislado.
const express = require("express");
const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");

const { tickets } = require("./data");

const app = express();
const COMPROBANTES_DIR = path.join(__dirname, "comprobantes");

app.get("/", (_req, res) => {
  res.type("text/plain").send(
    "Plataforma de Compra de Tickets — laboratorio CENTINELA (datos sinteticos)\n" +
      "Endpoints: /tickets  /comprobante?archivo=...  /validar?codigo=..."
  );
});

app.get("/tickets", (_req, res) => {
  res.json(tickets);
});

app.get("/ticket/:id", (req, res) => {
  const ticket = tickets.find((t) => t.id === Number(req.params.id));
  if (!ticket) return res.status(404).json({ error: "ticket no encontrado" });
  res.json(ticket);
});

// VULNERABILIDAD INTENCIONAL #1: path traversal.
// `archivo` se concatena directamente a la ruta base sin sanitizar ni
// validar que el resultado siga dentro de COMPROBANTES_DIR, permitiendo
// escapar con ../ hacia cualquier archivo legible por el proceso de Node.
app.get("/comprobante", (req, res) => {
  const archivo = req.query.archivo || "";
  // Vulnerable a propósito: NO usar path.basename() ni comprobar el
  // prefijo resuelto aquí. No replicar este patrón fuera del laboratorio.
  const ruta = path.join(COMPROBANTES_DIR, archivo);

  fs.readFile(ruta, "utf-8", (err, contenido) => {
    if (err) return res.status(404).type("text/plain").send(`Archivo no encontrado: ${archivo}`);
    res.type("text/plain").send(contenido);
  });
});

// VULNERABILIDAD INTENCIONAL #2: command injection.
// `codigo` se interpola directamente dentro de un comando de shell sin
// sanitizar, permitiendo encadenar comandos arbitrarios (;, |, &&, `` ` ``).
app.get("/validar", (req, res) => {
  const codigo = req.query.codigo || "";
  // Vulnerable a propósito: NO usar execFile() con argumentos separados
  // aquí. No replicar este patrón fuera del laboratorio.
  exec(`sh ./scripts/verificar.sh ${codigo}`, { cwd: __dirname }, (err, stdout, stderr) => {
    if (err) return res.status(500).type("text/plain").send(stderr || String(err));
    res.type("text/plain").send(stdout);
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`tickets-vulnerable escuchando en el puerto ${PORT}`);
});
