
function encryptAES() {
    const plaintext = document.getElementById("plaintext").value;
    const key = document.getElementById("key").value;

    if (key.length !== 4) {
        alert("La clé doit avoir exactement 4 caractères.");
        return;
    }

    const ciphertext = CryptoJS.AES.encrypt(plaintext, key).toString();
    document.getElementById("resultAES").value = ciphertext;
}

function decryptAES() {
    const ciphertext = document.getElementById("resultAES").value;
    const key = document.getElementById("key").value;

    if (key.length !== 4) {
        alert("La clé doit avoir exactement 4 caractères.");
        return;
    }

    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    const plaintext = bytes.toString(CryptoJS.enc.Utf8);
    document.getElementById("plaintext").value = plaintext || "Erreur de déchiffrement.";
}

let rsaKeyPair;

async function generateRSAKeys() {
    rsaKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey);

    document.getElementById("publicKey").value = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
    document.getElementById("privateKey").value = btoa(String.fromCharCode(...new Uint8Array(privateKey)));
}

async function encryptRSA() {
    const message = document.getElementById("message").value;

    if (!rsaKeyPair) {
        alert("Veuillez d'abord générer des clés RSA.");
        return;
    }

    const encodedMessage = new TextEncoder().encode(message);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.publicKey,
        encodedMessage
    );

    document.getElementById("resultRSA").value = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptRSA() {
    const encrypted = document.getElementById("resultRSA").value;

    if (!rsaKeyPair) {
        alert("Veuillez d'abord générer des clés RSA.");
        return;
    }

    const decoded = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaKeyPair.privateKey,
        decoded
    );

    document.getElementById("message").value = new TextDecoder().decode(decrypted);
}


function hashSHA() {
    const input = document.getElementById("hashInput").value;
    const hash = CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
    document.getElementById("hashResult").value = hash;
}

document.addEventListener('DOMContentLoaded', function () {
    let publicKey, privateKey;

   
    async function generateKeys() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: { name: "SHA-256" }
            },
            true,
            ["sign", "verify"]
        );
        publicKey = keyPair.publicKey;
        privateKey = keyPair.privateKey;


        const exportedPublicKey = await exportKey(publicKey);
        const exportedPrivateKey = await exportKey(privateKey);
        
        document.getElementById('public-key').innerText = `Clé publique : ${exportedPublicKey}`;
        document.getElementById('private-key').innerText = `Clé privée : ${exportedPrivateKey}`;
    }


    async function signMessage() {
        const message = document.getElementById('message').value;
        const enc = new TextEncoder();
        const encodedMessage = enc.encode(message);

        const signature = await window.crypto.subtle.sign(
            {
                name: "RSASSA-PKCS1-v1_5",
            },
            privateKey,
            encodedMessage
        );

      
        const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
        document.getElementById('signature').innerText = `Signature : ${base64Signature}`;
    }

    async function verifySignature() {
        const message = document.getElementById('message').value;
        const signatureBase64 = document.getElementById('signature').innerText.replace('Signature : ', '');
        const signature = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

        const enc = new TextEncoder();
        const encodedMessage = enc.encode(message);

        const isValid = await window.crypto.subtle.verify(
            {
                name: "RSASSA-PKCS1-v1_5",
            },
            publicKey,
            signature,
            encodedMessage
        );

        document.getElementById('verification-result').innerText = isValid
            ? "Signature valide !"
            : "Signature invalide.";
    }


    async function exportKey(key) {
        const exported = await window.crypto.subtle.exportKey('spki', key);
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }


    document.getElementById('generate-keys-btn').addEventListener('click', generateKeys);
    document.getElementById('sign-btn').addEventListener('click', signMessage);
    document.getElementById('verify-btn').addEventListener('click', verifySignature);
});
