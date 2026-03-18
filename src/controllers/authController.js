const authService = require("../services/authService"); 
const User = require("../models/User"); 


exports.register = async (req, res) => {
  console.log("Dane otrzymane z formularza rejestracji:", req.body);
  try {
    const { first_name, last_name, email, password } = req.body;

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "Email już istnieje" });
    }


    const user = await User.create({
      first_name,
      last_name,
      email,
      password,
    });


    res.status(201).json(user.safeResponse());
  } catch (error) {
    console.error("Błąd rejestracji:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

   
    if (!email || !password) {
      return res.status(400).json({ error: "Email i hasło są wymagane." });
    }


    const result = await authService.login(email, password);

  
    res.cookie("token", result.token, {
      httpOnly: true, // Ochrona przed dostępem przez JavaScript
      secure: process.env.NODE_ENV === "production", // HTTPS w trybie produkcyjnym
      sameSite: "strict", // Zapobieganie atakom CSRF
      maxAge: 24 * 60 * 60 * 1000, // Ważność 24 godziny
    });

 
    return res.status(200).json({ success: true, user: result.user });
  } catch (error) {
   
    return res.status(401).json({ success: false, error: error.message });
  }
};


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

exports.getProfile = async (req, res) => {
  try {
  
    const user = await User.findByPk(req.userId, {
      attributes: { exclude: ["password"] }, 
    });


    if (!user) {
      return res
        .status(404)
        .json({ success: false, error: "Użytkownik nie znaleziony." });
    }


    return res.status(200).json({ success: true, user });
  } catch (error) {
  
    return res.status(400).json({ success: false, error: error.message });
  }
};


exports.adminPanel = (req, res) => {
  try {
    return res
      .status(200)
      .json({ success: true, message: "Witaj w panelu admina!" });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Błąd podczas dostępu do panelu admina.",
    });
  }
};
