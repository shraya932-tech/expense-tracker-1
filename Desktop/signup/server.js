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
