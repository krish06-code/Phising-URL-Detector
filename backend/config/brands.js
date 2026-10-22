/**
 * brands.js
 * =========
 * Configurable registry of protected brands, their associated keywords,
 * and their verified official registered domains.
 *
 * Used by brandDetector.js to identify:
 * 1. Legitimate official domains (should never be flagged as impersonating themselves)
 * 2. Misleading subdomains (e.g. amazon.com.example.net)
 * 3. Typosquatting / homoglyphs (e.g. amaz0n.com, paypa1.com)
 * 4. Combosquatting (e.g. paypal-security-update.com)
 *
 * To add a new protected brand, simply add an object to the PROTECTED_BRANDS array.
 */

const PROTECTED_BRANDS = [
  {
    id: "google",
    name: "Google",
    keywords: ["google", "gmail"],
    officialDomains: [
      "google.com",
      "google.co.uk",
      "google.ca",
      "google.de",
      "google.fr",
      "google.co.in",
      "google.co.jp",
      "google.com.au",
      "google.com.br",
      "gmail.com",
      "youtube.com",
      "android.com",
      "gstatic.com",
      "googleusercontent.com",
      "googleapis.com",
    ],
  },
  {
    id: "amazon",
    name: "Amazon",
    keywords: ["amazon", "primevideo", "aws"],
    officialDomains: [
      "amazon.com",
      "amazon.co.uk",
      "amazon.de",
      "amazon.ca",
      "amazon.fr",
      "amazon.it",
      "amazon.es",
      "amazon.in",
      "amazon.co.jp",
      "amazon.com.au",
      "amazon.com.br",
      "amazon.com.mx",
      "media-amazon.com",
      "primevideo.com",
      "aws.amazon.com",
      "amazonwebservices.com",
    ],
  },
  {
    id: "microsoft",
    name: "Microsoft",
    keywords: ["microsoft", "outlook", "office365", "onedrive", "azure"],
    officialDomains: [
      "microsoft.com",
      "live.com",
      "office.com",
      "office365.com",
      "outlook.com",
      "hotmail.com",
      "bing.com",
      "msn.com",
      "microsoftonline.com",
      "windows.com",
      "azure.com",
      "sharepoint.com",
    ],
  },
  {
    id: "paypal",
    name: "PayPal",
    keywords: ["paypal"],
    officialDomains: [
      "paypal.com",
      "paypal.me",
      "paypal-community.com",
    ],
  },
  {
    id: "chatgpt",
    name: "ChatGPT / OpenAI",
    keywords: ["chatgpt", "openai"],
    officialDomains: [
      "openai.com",
      "chatgpt.com",
      "oaistatic.com",
      "oaiusercontent.com",
    ],
  },
  {
    id: "apple",
    name: "Apple",
    keywords: ["apple", "icloud"],
    officialDomains: [
      "apple.com",
      "icloud.com",
      "itunes.com",
      "me.com",
    ],
  },
  {
    id: "netflix",
    name: "Netflix",
    keywords: ["netflix"],
    officialDomains: [
      "netflix.com",
      "nflxext.com",
      "nflximg.net",
      "nflxvideo.net",
    ],
  },
  {
    id: "facebook",
    name: "Facebook / Meta",
    keywords: ["facebook", "instagram", "whatsapp", "meta"],
    officialDomains: [
      "facebook.com",
      "fb.com",
      "meta.com",
      "instagram.com",
      "whatsapp.com",
      "messenger.com",
    ],
  },
  {
    id: "github",
    name: "GitHub",
    keywords: ["github"],
    officialDomains: [
      "github.com",
      "github.io",
      "githubusercontent.com",
      "githubassets.com",
    ],
  },
  {
    id: "chase",
    name: "Chase Bank",
    keywords: ["chase", "chasebank"],
    officialDomains: [
      "chase.com",
    ],
  },
  {
    id: "wellsfargo",
    name: "Wells Fargo",
    keywords: ["wellsfargo"],
    officialDomains: [
      "wellsfargo.com",
    ],
  },
  {
    id: "bankofamerica",
    name: "Bank of America",
    keywords: ["bankofamerica", "bofa"],
    officialDomains: [
      "bankofamerica.com",
      "bofa.com",
    ],
  },
];

// Deceptive words often combined with brands in phishing URLs (combosquatting)
const SUSPICIOUS_AFFIXES = [
  "login",
  "signin",
  "sign-in",
  "log-in",
  "verify",
  "verification",
  "security",
  "secure",
  "account",
  "update",
  "support",
  "service",
  "help",
  "billing",
  "portal",
  "auth",
  "authorize",
  "wallet",
  "recover",
  "recovery",
  "alert",
  "manage",
  "confirm",
  "confirmation",
  "banking",
  "payment",
];

module.exports = {
  PROTECTED_BRANDS,
  SUSPICIOUS_AFFIXES,
};
