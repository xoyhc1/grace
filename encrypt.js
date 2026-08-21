const fs = require("fs");
const crypto = require("crypto");

const inputFile = process.argv[2];
const outputFile = process.argv[3];
const password = process.argv[4];

if (!inputFile || !outputFile || !password) {
    console.log("Usage:");
    console.log("node encrypt.js index.html locked.html 'your-password'");
    process.exit(1);
}

const html = fs.readFileSync(inputFile, "utf8");

// Random values; these are safe to store publicly
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);

// Derive AES key from password
const key = crypto.pbkdf2Sync(
    password,
    salt,
    250000,
    32,
    "sha256"
);

// Encrypt
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

const encrypted = Buffer.concat([
    cipher.update(html, "utf8"),
    cipher.final()
]);

const authTag = cipher.getAuthTag();

// Store ciphertext + authentication tag
const combined = Buffer.concat([
    encrypted,
    authTag
]);

const loader = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Protected</title>
</head>

<body>

<script>
(async () => {

    const encryptedData = "${combined.toString("base64")}";
    const saltData = "${salt.toString("base64")}";
    const ivData = "${iv.toString("base64")}";

    function fromBase64(str) {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    }

    const password = prompt("Enter password:");

    if (password === null) {
        document.body.innerHTML = "Access cancelled.";
        return;
    }

    try {

        const encoder = new TextEncoder();

        const passwordKey = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: fromBase64(saltData),
                iterations: 250000,
                hash: "SHA-256"
            },
            passwordKey,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: fromBase64(ivData),
                tagLength: 128
            },
            key,
            fromBase64(encryptedData)
        );

        const html = new TextDecoder().decode(decrypted);

        document.open();
        document.write(html);
        document.close();

    } catch (error) {

        document.body.innerHTML = \`
            <h2>Wrong password</h2>
            <button onclick="location.reload()">Try again</button>
        \`;

    }

})();
</script>

</body>
</html>`;

fs.writeFileSync(outputFile, loader);

console.log("Encrypted successfully:");
console.log(outputFile);