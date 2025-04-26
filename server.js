require("dotenv").config();
const express = require("express");
const cors = require("cors");
const sequelize = require("./src/config/db");
const authRoutes = require("./src/routes/authRoutes");
const cookieParser = require("cookie-parser");
const { authenticate } = require("./src/middleware/auth");

const app = express();
const PORT = process.env.PORT || 4000;

// ✅ ROZSZERZONA konfiguracja CORS
const corsOptions = {
  origin: "http://localhost:3000",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Jawne metody
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true,
  optionsSuccessStatus: 200, // Dla starszych przeglądarek
};

// 🔥 ZASTOSUJ CORS PRZED WSZYSTKIM
app.use(cors(corsOptions));

// Dodatkowe ręczne nagłówki dla pewności
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://localhost:3000");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  next();
});

// Obsługa preflight dla WSZYSTKICH ścieżek
app.options("*", cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 🔌 Połączenie z bazą danych (bez zmian)
sequelize
  .authenticate()
  .then(() => {
    console.log("Połączono z bazą danych!");
    if (process.env.NODE_ENV !== "production") {
      return sequelize.sync({ alter: true });
    }
    return Promise.resolve();
  })
  .then(() => {
    console.log("Modele zsynchroniczowane.");
  })
  .catch((err) => {
    console.error("Błąd bazy danych:", err);
    process.exit(1);
  });

// 📦 Trasy API (bez zmian)
app.use("/api/auth", authRoutes);

// 🔁 Endpoint testowy z JAWNYMI nagłówkami
app.get("/api/message", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.json({ message: "Witaj z backendu Express!" });
});

// 🔐 Endpoint currentUser z nagłówkami
app.get("/api/auth/currentUser", authenticate(), (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(200).json({
    user: req.user,
    message: "Zalogowany użytkownik",
  });
});

// ❌ Obsługa 404 (bez zmian)
app.use((req, res) => {
  res.status(404).json({
    status: "error",
    message: "Nie znaleziono zasobu",
    path: req.originalUrl,
  });
});

// 🧯 Globalna obsługa błędów (bez zmian)
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Błąd:`, err.stack);
  res.status(err.status || 500).json({
    status: "error",
    message: err.message || "Wystąpił błąd serwera",
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
});

// 🚀 Uruchomienie serwera (bez zmian)
const server = app.listen(PORT, () => {
  console.log(`Serwer działa na http://localhost:${PORT}`);
});

process.on("unhandledRejection", (err) => {
  console.error("Nieobsłużony błąd:", err);
  server.close(() => process.exit(1));
});
