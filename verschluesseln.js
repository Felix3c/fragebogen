// Verschlüsselt die Antworten im Browser, bevor irgendetwas die Seite verlässt.
// Block: "SF1:" + Base64( RSA-OAEP-SHA256(AES-Schlüssel) || IV (12 Byte) || AES-GCM(JSON) )
// Gegenstück zum Entschlüsseln: werkzeug.py (nur auf Felix' Laptop).
const PRAEFIX = "SF1:";

function pemZuBytes(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (z) => z.charCodeAt(0));
}

function bytesZuB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

async function verschluesseln(text, oeffentlichPem) {
  const rsa = await crypto.subtle.importKey(
    "spki", pemZuBytes(oeffentlichPem), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const inhalt = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(text)));
  const rohSchluessel = new Uint8Array(await crypto.subtle.exportKey("raw", aes));
  const verpackt = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsa, rohSchluessel));

  const alles = new Uint8Array(verpackt.length + iv.length + inhalt.length);
  alles.set(verpackt, 0);
  alles.set(iv, verpackt.length);
  alles.set(inhalt, verpackt.length + iv.length);
  return PRAEFIX + bytesZuB64(alles);
}

if (typeof module !== "undefined") module.exports = { verschluesseln };
