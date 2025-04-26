const { check, validationResult } = require("express-validator");
const User = require("../models/User");

exports.validateRegister = [
  // Sprawdzenie podstawowych pól
  check("confirmPassword")
    .notEmpty()
    .withMessage("Potwierdzenie hasła jest wymagane")
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Hasła nie są identyczne");
      }
      return true;
    }),
  check("first_name")
    .trim()
    .notEmpty()
    .withMessage("Imię jest wymagane")
    .isLength({ min: 2 })
    .withMessage("Imię musi mieć co najmniej 2 znaki")
    .matches(/^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$/)
    .withMessage("Imię może zawierać tylko litery"),

  check("last_name")
    .trim()
    .notEmpty()
    .withMessage("Nazwisko jest wymagane")
    .isLength({ min: 2 })
    .withMessage("Nazwisko musi mieć co najmniej 2 znaki")
    .matches(/^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ\s-]+$/)
    .withMessage("Nazwisko zawiera niedozwolone znaki"),

  check("email")
    .trim()
    .notEmpty()
    .withMessage("Email jest wymagany")
    .isEmail()
    .withMessage("Podaj poprawny adres email")
    .normalizeEmail()
    .custom(async (email) => {
      const user = await User.findOne({ where: { email } });
      if (user) {
        throw new Error("Email już istnieje w systemie");
      }
    }),

  check("password")
    .notEmpty()
    .withMessage("Hasło jest wymagane")
    .isLength({ min: 8 })
    .withMessage("Hasło musi mieć co najmniej 8 znaków")
    .matches(/[a-z]/)
    .withMessage("Hasło musi zawierać małą literę")
    .matches(/[A-Z]/)
    .withMessage("Hasło musi zawierać wielką literę")
    .matches(/\d/)
    .withMessage("Hasło musi zawierać cyfrę")
    .matches(/[@$!%*?&]/)
    .withMessage("Hasło musi zawierać znak specjalny (@$!%*?&)"),

  // Middleware do sprawdzania wyników walidacji
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array().map((err) => ({
          field: err.path,
          message: err.msg,
        })),
      });
    }
    next();
  },
];

// Dodatkowa walidacja dla logowania
exports.validateLogin = [
  check("email")
    .trim()
    .notEmpty()
    .withMessage("Email jest wymagany")
    .isEmail()
    .withMessage("Podaj poprawny adres email"),

  check("password").notEmpty().withMessage("Hasło jest wymagane"),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }
    next();
  },
];
