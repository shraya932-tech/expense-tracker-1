const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, before, test } = require("node:test");
const { createApp } = require("../server");

let server;
let service;
let baseUrl;
let databasePath;
let temporaryDirectory;

before(async () => {
    temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "signup-api-"));
    databasePath = path.join(temporaryDirectory, "signup.sqlite");
    service = createApp(databasePath);
    server = await new Promise((resolve) => {
        const listeningServer = service.app.listen(0, "127.0.0.1", () => {
            resolve(listeningServer);
        });
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
    await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
    });
    service.close();
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

test("creates a user with a bcrypt password hash", async () => {
    const response = await fetch(`${baseUrl}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            name: "Test User",
            email: "Test@Example.com",
            password: "correct horse battery"
        })
    });
    const result = await response.json();

    assert.equal(response.status, 201);
    assert.equal(result.message, "Signup successful!");
    assert.equal(result.user.email, "test@example.com");
    assert.equal(Object.hasOwn(result.user, "password"), false);

    const Database = require("better-sqlite3");
    const database = new Database(databasePath, { readonly: true });
    const storedUser = database.prepare("SELECT * FROM users WHERE email = ?").get("test@example.com");
    database.close();

    assert.notEqual(storedUser.password_hash, "correct horse battery");
    assert.equal(await bcrypt.compare("correct horse battery", storedUser.password_hash), true);
});

test("returns 409 when an email already exists (case-insensitive)", async () => {
    const response = await fetch(`${baseUrl}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            name: "Another User",
            email: "TEST@example.com",
            password: "another password"
        })
    });

    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { message: "User already exists" });
});

test("rejects missing fields, invalid emails, and short passwords", async () => {
    const invalidRequests = [
        [{ name: "Missing email", password: "long enough" }, "All fields are required"],
        [{ name: "Invalid email", email: "not-an-email", password: "long enough" }, "Please enter a valid email"],
        [{ name: "Short password", email: "short@example.com", password: "1234567" }, "Password must be at least 8 characters"]
    ];

    for (const [body, message] of invalidRequests) {
        const response = await fetch(`${baseUrl}/signup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { message });
    }
});

test("returns a JSON validation error for malformed JSON", async () => {
    const response = await fetch(`${baseUrl}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{"
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { message: "Invalid JSON request" });
});
