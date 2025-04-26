const authService = require("../services/authService"); // Import serwisu autoryzacji
const User = require("../models/User"); // Import modelu użytkownika (potrzebny w getProfile)

// Rejestracja użytkownika
exports.register = async (req, res) => {
  console.log("Dane otrzymane z formularza rejestracji:", req.body);
  try {
    const { first_name, last_name, email, password } = req.body;

    // Sprawdź czy użytkownik już istnieje
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "Email już istnieje" });
    }

    // Utwórz nowego użytkownika (hasło zostanie zahashowane przez hook)
    const user = await User.create({
      first_name,
      last_name,
      email,
      password,
    });

    // Zwróć dane bez hasła
    res.status(201).json(user.safeResponse());
  } catch (error) {
    console.error("Błąd rejestracji:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
};
// Logowanie użytkownika
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Walidacja danych wejściowych
    if (!email || !password) {
      return res.status(400).json({ error: "Email i hasło są wymagane." });
    }

    // Wywołanie serwisu
    const result = await authService.login(email, password);

    // Zapis tokenu JWT w ciasteczku
    res.cookie("token", result.token, {
      httpOnly: true, // Ochrona przed dostępem przez JavaScript
      secure: process.env.NODE_ENV === "production", // HTTPS w trybie produkcyjnym
      sameSite: "strict", // Zapobieganie atakom CSRF
      maxAge: 24 * 60 * 60 * 1000, // Ważność 24 godziny
    });

    // Sukces
    return res.status(200).json({ success: true, user: result.user });
  } catch (error) {
    // Obsługa błędów
    return res.status(401).json({ success: false, error: error.message });
  }
};

// Wylogowanie użytkownika
exports.logout = (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
  });
  res.json({
    success: true,
    message: "Wylogowano pomyślnie",
  });
};
// Profil użytkownika
exports.getProfile = async (req, res) => {
  try {
    // Pobranie użytkownika na podstawie userId z middleware
    const user = await User.findByPk(req.userId, {
      attributes: { exclude: ["password"] }, // Wykluczanie hasła
    });

    // Sprawdzenie, czy użytkownik istnieje
    if (!user) {
      return res
        .status(404)
        .json({ success: false, error: "Użytkownik nie znaleziony." });
    }

    // Sukces
    return res.status(200).json({ success: true, user });
  } catch (error) {
    // Obsługa błędów
    return res.status(400).json({ success: false, error: error.message });
  }
};

// Panel administratora
exports.adminPanel = (req, res) => {
  try {
    // Sprawdzenie roli w middleware authenticate (np. role_id = 1)
    return res
      .status(200)
      .json({ success: true, message: "Witaj w panelu admina!" });
  } catch (error) {
    // Obsługa błędów (opcjonalnie)
    return res.status(500).json({
      success: false,
      error: "Błąd podczas dostępu do panelu admina.",
    });
  }
};
