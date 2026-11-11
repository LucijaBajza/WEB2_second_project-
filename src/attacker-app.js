import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = Number(4000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "attacker-site")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Napadačka stranica dostupna je na http://localhost:${PORT}`);
});
