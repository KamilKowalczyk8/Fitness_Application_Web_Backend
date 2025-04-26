const jwt = require("jsonwebtoken");
/**
 * Middleware autentykacji z kontrolą dostępu opartą na rolach
 * @param {Array<string>} roles - Lista dozwolonych ról (opcjonalna)
 * @returns {Function} Middleware funkcja
 */
exports.authenticate = (roles = []) => {
  return async (req, res, next) => {
    try {
      // 1. Pobierz token z różnych źródeł
      const token =
        req.header("Authorization")?.replace("Bearer ", "") ||
        req.cookies?.token ||
        req.query?.token;

      if (!token) {
        return res.status(401).json({
          success: false,
          error: "Brak tokenu autoryzacyjnego",
          code: "MISSING_AUTH_TOKEN",
        });
      }

      // 2. Weryfikacja tokena
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ["HS256"],
      });

      // 3. Sprawdzenie ważności tokena (jeśli masz wersję z expiresIn)
      if (decoded.exp && Date.now() >= decoded.exp * 1000) {
        return res.status(401).json({
          success: false,
          error: "Token wygasł",
          code: "TOKEN_EXPIRED",
        });
      }

      // 4. Walidacja struktury tokena
      if (!decoded.userId || !decoded.roleId) {
        return res.status(401).json({
          success: false,
          error: "Nieprawidłowa struktura tokena",
          code: "INVALID_TOKEN_STRUCTURE",
        });
      }

      // 5. Kontrola dostępu oparta na rolach
      if (roles.length > 0 && !roles.includes(decoded.roleId)) {
        return res.status(403).json({
          success: false,
          error: "Brak uprawnień do tego zasobu",
          requiredRoles: roles,
          userRole: decoded.roleId,
          code: "INSUFFICIENT_PERMISSIONS",
        });
      }

      // 6. Dołącz pełne dane użytkownika do requestu
      req.user = {
        id: decoded.userId,
        role: decoded.roleId,
        // Możesz dodać więcej pól z tokena jeśli są potrzebne
        ...(decoded.email && { email: decoded.email }),
        ...(decoded.refreshToken && { refreshToken: decoded.refreshToken }),
      };

      // 7. Logowanie sukcesu (tylko w development)
      if (process.env.NODE_ENV === "development") {
        console.log(
          `Zautentykowany użytkownik ID: ${decoded.userId}, Rola: ${decoded.roleId}`
        );
      }

      next();
    } catch (err) {
      // Obsługa różnych typów błędów JWT
      let errorMessage = "Nieprawidłowy token";
      let errorCode = "INVALID_TOKEN";

      if (err.name === "TokenExpiredError") {
        errorMessage = "Token wygasł";
        errorCode = "TOKEN_EXPIRED";
      } else if (err.name === "JsonWebTokenError") {
        errorMessage = "Nieprawidłowa sygnatura tokena";
        errorCode = "INVALID_SIGNATURE";
      }

      res.status(401).json({
        success: false,
        error: errorMessage,
        code: errorCode,
        ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
      });
    }
  };
};

// Dodatkowa funkcja do generowania tokenów
function generateToken(userId) {
  // Upewnij się, że JWT_SECRET jest ustawiony w .env!
  if (!process.env.JWT_SECRET) {
    throw new Error("Brak JWT_SECRET w zmiennych środowiskowych");
  }

  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: "24h" } // Dostosuj czas ważności
  );
}
// Middleware do odświeżania tokena (opcjonalne)
exports.refreshTokenMiddleware = (req, res, next) => {
  // Implementacja odświeżania tokena
  // ...
};
