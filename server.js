const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURACIÓN ---
app.use(express.json());
app.use(express.static(__dirname));

// --- BASE DE DATOS (SQLite) ---
const dbFile = path.join(__dirname, "auth.db");
const db = new sqlite3.Database(dbFile);

// Crear tabla si no existe
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

// --- RUTA PRINCIPAL ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- REGISTRO ---
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: "Faltan campos" });

  // Hashear la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insertar usuario en DB
  const query = "INSERT INTO users (username, password) VALUES (?, ?)";
  db.run(query, [username, hashedPassword], function (err) {
    if (err) {
      if (err.message.includes("UNIQUE")) {
        return res.status(409).json({ message: "El usuario ya existe" });
      }
      console.error(err);
      return res.status(500).json({ message: "Error en el servidor" });
    }
    res.status(201).json({ message: "Usuario registrado con éxito" });
  });
});

// --- LOGIN ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: "Faltan campos" });

  const query = "SELECT * FROM users WHERE username = ?";
  db.get(query, [username], async (err, user) => {
    if (err) return res.status(500).json({ message: "Error en el servidor" });
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(401).json({ message: "Contraseña incorrecta" });

    res.json({ message: "Login exitoso" });
  });
});

// --- INICIAR SERVIDOR ---
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});
