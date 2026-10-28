const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const appDirectory = __dirname;
const schemaPath = path.join(appDirectory, "database", "init.sql");

function createApp(databasePath = path.join(appDirectory, "data", "signup.sqlite")) {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });

    const database = new Database(databasePath);
    database.pragma("journal_mode = WAL");
    database.exec(fs.readFileSync(schemaPath, "utf8"));

    const insertUser = database.prepare(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
    );
    const findUserByEmail = database.prepare(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?"
    );
    const serverApp = express();

    serverApp.use(express.json());
    serverApp.use(express.urlencoded({ extended: true }));
    serverApp.use(express.static(path.join(appDirectory, "public")));

    serverApp.post("/signup", async (req, res, next) => {
        const { name, email, password } = req.body ?? {};

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            !name.trim() ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const normalizedEmail = email.trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({ message: "Please enter a valid email" });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters"
            });
        }

        try {
            const passwordHash = await bcrypt.hash(password, 12);
            const result = insertUser.run(name.trim(), normalizedEmail, passwordHash);

            return res.status(201).json({
                message: "Signup successful!",
                user: { id: result.lastInsertRowid, name: name.trim(), email: normalizedEmail }
            });
        } catch (error) {
            if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
                return res.status(409).json({ message: "User already exists" });
            }

            return next(error);
        }
    });

    serverApp.post("/login", async (req, res, next) => {
        const { email, password } = req.body ?? {};

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const normalizedEmail = email.trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({ message: "Please enter a valid email" });
        }

        try {
            const user = findUserByEmail.get(normalizedEmail);
            const passwordMatches = user
                ? await bcrypt.compare(password, user.password_hash)
                : false;

            if (!passwordMatches) {
                return res.status(401).json({ message: "Invalid email or password" });
            }

            return res.status(200).json({
                message: "Login successful!",
                user: { id: user.id, name: user.name, email: user.email }
            });
        } catch (error) {
            return next(error);
        }
    });

    serverApp.use((error, req, res, next) => {
        if (res.headersSent) {
            return next(error);
        }

        if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
            return res.status(400).json({ message: "Invalid JSON request" });
        }

        console.error("Request failed:", error);
        return res.status(500).json({ message: "Internal server error" });
    });

    return {
        app: serverApp,
        close: () => database.close()
    };
}

if (require.main === module) {
    const { app: serverApp } = createApp();
    const port = Number(process.env.PORT) || 3000;
    serverApp.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}

module.exports = { createApp };
