-- Datos 100% sintéticos (nombres, cédulas y montos inventados) para el
-- objetivo de laboratorio "gov-pago". Nunca datos reales de ciudadanos.
CREATE TABLE IF NOT EXISTS contribuyentes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    cedula          VARCHAR(16) NOT NULL,
    nombre          VARCHAR(128) NOT NULL,
    monto_adeudado  DECIMAL(10,2) NOT NULL,
    periodo         VARCHAR(16) NOT NULL
);

INSERT INTO contribuyentes (cedula, nombre, monto_adeudado, periodo) VALUES
    ('V11111111', 'Maria Perez (ficticio)',   150.50, '2026-Q1'),
    ('V22222222', 'Juan Gomez (ficticio)',     320.00, '2026-Q1'),
    ('V33333333', 'Ana Rodriguez (ficticio)',   0.00,  '2026-Q1'),
    ('V44444444', 'Carlos Mendoza (ficticio)', 980.25, '2026-Q1'),
    ('V55555555', 'Lucia Fernandez (ficticio)', 45.00, '2026-Q1');
