require("dotenv").config();
const bcrypt = require("bcrypt");

async function testPassword() {
  // Pobierz hash z bazy dla testowego użytkownika
  const dbHash = "$2b$10$15E5LeMBBXiAYRJr5FF1xOehwt1b.dP0mvkj6ipALpLfqznsa9MuW"; // Zastąp tym z bazy

  const isMatch = await bcrypt.compare("Strongpassword!1", dbHash);
  console.log("Wynik porównania:", isMatch);

  // Możesz też wygenerować nowy hash dla testów
  const newHash = await bcrypt.hash("Strongpassword!1", 10);
  console.log("Nowy hash:", newHash);
}

testPassword();
