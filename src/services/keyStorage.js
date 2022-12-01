import crypto from 'crypto';
import fs from 'fs';
const subtle = crypto.subtle;

// Following Mozilla guide on IndexedDB https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Using_IndexedDB
// Salt length: 16 bytes or 128-bits https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
// Iterations for PBKDF2 with PBKDF2-HMAC-SHA256: 310,000 https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const passSaltSize = 16;
const ivSize = 16;
const sha256Length = 256;
const pbkdf2IterSHA256 = 310000;
const pbkdf2IterSHA512 = 120000;
const hashFile = "hashes.bin";
const encFile = 'enc.bin';
let sessionPass = null;

async function passwordToPBKDF2(password, salt)
{
    const passwordKey = await subtle.importKey('raw', (new TextEncoder()).encode(password), {name: 'PBKDF2'}, false, ['deriveBits', 'deriveKey']);
    const hash = await subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: pbkdf2IterSHA256,
            hash: 'SHA-256'
        },
        passwordKey,
        sha256Length
    );
    return hash;
}

async function genAuthEncKey(password, keySalt)
{
    const keyBits = await subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-512',
            salt: keySalt,
            iterations: pbkdf2IterSHA512
        },
        await subtle.importKey('raw', (new TextEncoder()).encode(password), {name: 'PBKDF2'}, false, ['deriveBits', 'deriveKey']),
        512
    );
    const encryptKey = await subtle.importKey(
        'raw',
        keyBits.slice(0, 32),
        {name: 'AES-CBC'},
        false,
        ['encrypt', 'decrypt']
    );
    const authKey = await subtle.importKey(
        'raw',
        keyBits.slice(32),
        {name: 'HMAC', hash: 'SHA-256'},
        false,
        ['sign', 'verify']
    );

    return {encryptKey, authKey};
}

async function createPassword(password)
{
    const salt = crypto.getRandomValues(new Uint8Array(passSaltSize));
    const hash = await passwordToPBKDF2(password, salt);
    fs.writeFileSync(hashFile, Buffer.concat([Buffer.from(salt), Buffer.from(hash)]));
}

async function checkPassword(password)
{
    const fileBuf = fs.readFileSync(hashFile);
    const salt = fileBuf.slice(0, passSaltSize);
    const passHash = Buffer.from(fileBuf.slice(passSaltSize)).toString('hex');
    const guessHash = Buffer.from(await passwordToPBKDF2(password, salt)).toString('hex');
    sessionPass = password;
    if (passHash == guessHash)
        return true;
    else
        return false;
}

async function encryptFiles(plaintext)
{
    const keySalt = crypto.getRandomValues(new Uint8Array(passSaltSize));
    const {authKey, encryptKey} = await genAuthEncKey(sessionPass, keySalt);
    const iv = crypto.getRandomValues(new Uint8Array(ivSize));
    const cipherText = await subtle.encrypt(
        {
            name: 'AES-CBC',
            iv: iv
        },
        encryptKey,
        (new TextEncoder).encode(plaintext)
    );
    const hmac = await subtle.sign(
        {name: 'HMAC'},
        authKey,
        Buffer.from(iv) + Buffer.from(cipherText)
    );
    fs.writeFileSync(encFile, Buffer.concat([keySalt, iv, Buffer.from(hmac), Buffer.from(cipherText)]));
}

async function decryptFiles()
{
    const sha256Bytes = sha256Length / 8;
    const dataBuf = fs.readFileSync(encFile);
    const keySalt = dataBuf.slice(0, passSaltSize);
    const iv = dataBuf.slice(passSaltSize, passSaltSize + ivSize);
    const hmac = dataBuf.slice(passSaltSize + ivSize, passSaltSize + ivSize + sha256Bytes);
    const ciphertext = dataBuf.slice(passSaltSize + ivSize + sha256Bytes);
    const {encryptKey, authKey} = await genAuthEncKey(sessionPass, keySalt);
    const verified = await subtle.verify({name: 'HMAC'}, authKey, hmac, iv + ciphertext);

    if (!verified)
        throw 'WARNING: ENCRYPTED FILES MODIFIED ILLEGALLY';

    const plaintext = await subtle.decrypt(
        {
            name: 'AES-CBC',
            iv: iv
        },
        encryptKey,
        ciphertext
    );

    return (new TextDecoder).decode(plaintext);
}

async function checkPasswordFileExists()
{
    return fs.existsSync(hashFile);
}

async function main() {
    const password = "asdf";
    await createPassword(password);
    console.log(await checkPassword(password));
    console.log(await checkPassword('abc'));
    await encryptFiles('hi');
    try {
        console.log(await decryptFiles());
    } catch(err)
    {
        console.log('file does not exist');
    }
    console.log(Date.now());
}

//main();

export default {createPassword, checkPassword, encryptFiles, decryptFiles, checkPasswordFileExists};
