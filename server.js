// server.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(cookieParser());

// Servir frontend estático (carpeta public)
app.use(express.static(path.join(__dirname, "public")));

// Configuración (en producción usa variables de entorno)
const JWT_SECRET = process.env.JWT_SECRET || "CAMBIA_ESTO_POR_ALGO_MUY_SECRETO";
const JWT_EXPIRES = "7d";
const COOKIE_NAME = "sid";

// Inicializar DB SQLite
let db;
async function initDb() {
  db = await open({
    filename: path.join(__dirname, "auth.db"),
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      passwordHash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

await initDb();

// Helper: crear token JWT
function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// Endpoint: REGISTER
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Faltan datos" });

    const emailLc = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLc)) {
      return res.status(400).json({ message: "Email inválido" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "La contraseña debe tener al menos 6 caracteres" });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    try {
      const result = await db.run(
        "INSERT INTO users (email, passwordHash) VALUES (?, ?)",
        emailLc,
        passwordHash
      );
      return res.status(201).json({ message: "Usuario creado", id: result.lastID });
    } catch (dbErr) {
      if (dbErr && dbErr.code === "SQLITE_CONSTRAINT") {
        return res.status(409).json({ message: "El correo ya está registrado" });
      }
      console.error(dbErr);
      return res.status(500).json({ message: "Error al crear usuario" });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno" });
  }
});

// Endpoint: LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Faltan datos" });

    const emailLc = email.trim().toLowerCase();
    const row = await db.get("SELECT id, email, passwordHash FROM users WHERE email = ?", emailLc);
    if (!row) return res.status(401).json({ message: "Correo o contraseña incorrectos" });

    const match = await bcrypt.compare(password, row.passwordHash);
    if (!match) return res.status(401).json({ message: "Correo o contraseña incorrectos" });

    const token = createToken({ sub: row.id, email: row.email });

    // Enviar cookie httpOnly. En desarrollo secure=false (http://localhost)
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Devolver redirect para que el frontend redirija al usuario a la tienda
    return res.json({ message: "Autenticado", redirect: "https://mfraud.onrender.com" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno" });
  }
});

// Endpoint: ME (comprueba cookie)
app.get("/me", (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ message: "No autenticado" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ id: payload.sub, email: payload.email });
  } catch (err) {
    return res.status(401).json({ message: "Token inválido" });
  }
});

// Endpoint: LOGOUT
app.post("/logout", (req, res) => {
  res.cookie(COOKIE_NAME, "", { maxAge: 0, httpOnly: true, path: "/" });
  res.json({ message: "Cerró sesión" });
});

// DEBUG: listar usuarios (solo para desarrollo) - elimina o protege en producción
app.get("/users", async (req, res) => {
  const rows = await db.all("SELECT id, email, created_at FROM users ORDER BY id DESC");
  res.json(rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor funcionando en http://localhost:${PORT}`);
});
