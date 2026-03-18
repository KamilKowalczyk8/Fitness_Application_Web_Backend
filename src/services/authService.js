const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Op } = require("sequelize");

const PASSWORD_POLICY = {
  minLength: 8,
  requireUpper: true,
  requireLower: true,
  requireNumber: true,
  requireSpecial: true,
};

const TOKEN_CONFIG = {
  expiresIn: "24h",
  issuer: "your-app-name",
};

const validatePassword = (password) => {
  const errors = [];

  if (password.length < PASSWORD_POLICY.minLength) {
    errors.push(
      `Hasło musi mieć co najmniej ${PASSWORD_POLICY.minLength} znaków`
    );
  }

  if (PASSWORD_POLICY.requireUpper && !/[A-Z]/.test(password)) {
    errors.push("Hasło musi zawierać co najmniej jedną wielką literę");
  }

  if (PASSWORD_POLICY.requireLower && !/[a-z]/.test(password)) {
    errors.push("Hasło musi zawierać co najmniej jedną małą literę");
  }

  if (PASSWORD_POLICY.requireNumber && !/[0-9]/.test(password)) {
    errors.push("Hasło musi zawierać co najmniej jedną cyfrę");
  }

  if (PASSWORD_POLICY.requireSpecial && !/[@$!%*?&]/.test(password)) {
    errors.push(
      "Hasło musi zawierać co najmniej jeden znak specjalny (@$!%*?&)"
    );
  }

  return errors.length === 0 ? { valid: true } : { valid: false, errors };
};

const generateToken = (userId, roleId) => {
  return jwt.sign(
    {
      userId,
      roleId,
      iss: TOKEN_CONFIG.issuer,
      aud: "your-app-client",
    },
    process.env.JWT_SECRET,
    {
      expiresIn: TOKEN_CONFIG.expiresIn,
    }
  );
};

exports.register = async ({ first_name, last_name, email, password }) => {
  try {
    const normalizedEmail = email.toLowerCase().trim();

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      throw new Error(
        `Nieprawidłowe hasło: ${passwordValidation.errors.join(", ")}`
      );
    }

    const existingUser = await User.findOne({
      where: {
        email: {
          [Op.iLike]: normalizedEmail,
        },
      },
    });

    if (existingUser) {
      throw new Error("Email jest już zajęty");
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      first_name: first_name.trim(),
      last_name: last_name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      is_active: true,
      role_id: 2,
      last_password_change: new Date(),
    });

    const token = generateToken(user.user_id, user.role_id);

    return {
      user: user.safeResponse(), // Metoda do zdefiniowania w modelu
      token,
    };
  } catch (error) {
    console.error("Registration error:", error);
    throw new Error(error.message || "Wystąpił błąd podczas rejestracji");
  }
};

exports.login = async (email, password) => {
  try {
    const normalizedEmail = email.trim().toLowerCase();
    console.log(`[LOGIN] Próba logowania: ${normalizedEmail}`);

    const user = await User.findOne({
      where: {
        email: {
          [Op.eq]: normalizedEmail, 
        },
      },
      raw: true,
    });

    if (!user) {
      console.log("[LOGIN] Użytkownik nie istnieje");
      throw new Error("Nieprawidłowe dane logowania");
    }

    console.log(`[LOGIN] Znaleziono użytkownika:`, {
      id: user.id,
      is_active: user.is_active,
      password_hash: user.password.substring(0, 10) + "...",
    });

    if (!user.is_active) {
      throw new Error("Konto nieaktywne");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log(`[LOGIN] Wynik porównania haseł: ${isMatch}`);

    if (!isMatch) {
      throw new Error("Nieprawidłowe dane logowania");
    }

    const token = generateToken(user.id);
    console.log(`[LOGIN] Wygenerowano token: ${token.substring(0, 20)}...`);

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
      },
      token,
    };
  } catch (error) {
    console.error("[LOGIN] Błąd:", {
      input: { email, password: password ? "***" : null },
      error: error.message,
    });
    throw error;
  }
};
exports.logout = async (req, res) => {
  try {
    if (req.user && req.user.jti) {
      await TokenBlacklist.create({
        tokenId: req.user.jti,
        expiresAt: new Date(req.user.exp * 1000),
      });
    }

    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      domain: process.env.COOKIE_DOMAIN || "localhost",
    });

    return res.status(200).json({
      success: true,
      message: "Wylogowano pomyślnie",
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({
      success: false,
      error: "Wystąpił błąd podczas wylogowywania",
    });
  }
};
