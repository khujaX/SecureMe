// SecureMe front-end logic
// All sensitive processing is done client-side.

const $ = (selector) => document.querySelector(selector);

function smoothScrollTo(target) {
  const el = typeof target === "string" ? document.querySelector(target) : target;
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setupNavScrolling() {
  document.querySelectorAll("[data-scroll-target]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-scroll-target");
      if (target) smoothScrollTo(target);
    });
  });
}

function log2(x) {
  return Math.log(x) / Math.log(2);
}

function estimateEntropy(password) {
  if (!password) return 0;

  let charsetSize = 0;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigits = /\d/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);

  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasDigits) charsetSize += 10;
  if (hasSymbols) charsetSize += 32;
  if (!charsetSize) charsetSize = 10;

  return password.length * log2(charsetSize);
}

function strengthLabelFromScore(score) {
  switch (score) {
    case 0:
      return "Very weak";
    case 1:
      return "Weak";
    case 2:
      return "Fair";
    case 3:
      return "Strong";
    case 4:
      return "Very strong";
    default:
      return "–";
  }
}

function crackTimeLabel(seconds) {
  if (!seconds || !isFinite(seconds)) return "Unknown";
  const minute = 60;
  const hour = 60 * minute;
  const day = 24 * hour;
  const year = 365 * day;

  if (seconds < minute) return "Less than a minute";
  if (seconds < hour) return `${Math.round(seconds / minute)} min`;
  if (seconds < day) return `${Math.round(seconds / hour)} hours`;
  if (seconds < year) return `${Math.round(seconds / day)} days`;
  if (seconds < 100 * year) return `${Math.round(seconds / year)} years`;
  return "Centuries+";
}

function setupStrengthLab() {
  const input = $("#password-input");
  const bar = $("#strength-bar");
  const scoreLabel = $("#strength-score-label");
  const entropyValue = $("#entropy-value");
  const crackTime = $("#crack-time");
  const feedbackEl = $("#strength-summary");
  const toggleBtn = $("#toggle-password-visibility");

  if (!input) return;

  toggleBtn?.addEventListener("click", () => {
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.textContent = isPassword ? "Hide" : "Show";
    toggleBtn.setAttribute("aria-pressed", String(isPassword));
    toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });

  function updateStrength() {
    const value = input.value || "";
    if (!value) {
      bar.style.width = "0%";
      scoreLabel.textContent = "–";
      entropyValue.textContent = "–";
      crackTime.textContent = "–";
      feedbackEl.textContent = "Start typing to see detailed feedback.";
      return;
    }

    let score = 0;
    let suggestions = [];
    let warning = "";
    let secondsToCrack;

    if (typeof window.zxcvbn === "function") {
      const result = window.zxcvbn(value);
      score = result.score;
      warning = result.feedback.warning || "";
      suggestions = result.feedback.suggestions || [];
      secondsToCrack = result.crack_times_seconds.offline_slow_hashing_1e4_per_second;
    } else {
      const entropyBits = estimateEntropy(value);
      if (entropyBits < 28) score = 0;
      else if (entropyBits < 36) score = 1;
      else if (entropyBits < 60) score = 2;
      else if (entropyBits < 80) score = 3;
      else score = 4;

      if (value.length < 12) {
        warning = "Very short password. Aim for at least 12–16 characters.";
      } else if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) {
        warning = "Consider mixing letters and numbers for better resilience.";
      }
      suggestions = [
        "Prefer longer passwords or passphrases rather than adding random symbols.",
      ];
      const guesses = Math.pow(2, entropyBits);
      secondsToCrack = guesses / 1e8;
    }

    const width = ((score + 1) / 5) * 100;
    bar.style.width = `${width}%`;
    scoreLabel.textContent = strengthLabelFromScore(score);

    const entropyBits = estimateEntropy(value);
    entropyValue.textContent = `${entropyBits.toFixed(1)} bits (approx.)`;
    crackTime.textContent = crackTimeLabel(secondsToCrack);

    const pieces = [];
    pieces.push(`<strong>${strengthLabelFromScore(score)}</strong> password.`);
    if (warning) {
      pieces.push(warning);
    }
    if (suggestions.length) {
      pieces.push(suggestions.join(" "));
    }
    feedbackEl.innerHTML = pieces.join(" ");
  }

  input.addEventListener("input", updateStrength);
  updateStrength();
}

async function sha1Hex(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function hibpRangeQuery(prefix) {
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: {
      "Add-Padding": "true",
    },
  });
  if (!response.ok) {
    throw new Error(`HIBP API error: ${response.status}`);
  }
  return response.text();
}

function setupBreachChecker() {
  const input = $("#breach-input");
  const button = $("#breach-check-btn");
  const status = $("#breach-status");

  if (!input || !button || !status) return;

  button.addEventListener("click", async () => {
    const value = input.value || "";
    if (!value) {
      status.textContent = "Enter a password to check.";
      return;
    }

    button.disabled = true;
    status.textContent = "Hashing locally and querying HIBP…";

    try {
      const hash = await sha1Hex(value);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const body = await hibpRangeQuery(prefix);
      const lines = body.split("\n");

      let foundCount = 0;
      for (const line of lines) {
        const [lineSuffix, countStr] = line.trim().split(":");
        if (!lineSuffix) continue;
        if (lineSuffix.toUpperCase() === suffix) {
          foundCount = parseInt(countStr || "0", 10);
          break;
        }
      }

      if (foundCount > 0) {
        status.innerHTML = `⚠️ This password appears in known data breaches <strong>${foundCount.toLocaleString()}</strong> times. Choose a completely different password.`;
      } else {
        status.innerHTML =
          "✅ This password was not found in the HIBP corpus. Still avoid reusing it across sites.";
      }
    } catch (err) {
      console.error(err);
      status.textContent =
        "Could not complete the breach check (network or API issue). Try again later.";
    } finally {
      button.disabled = false;
    }
  });
}

function cryptoRandomInt(maxExclusive) {
  if (maxExclusive <= 0) throw new Error("maxExclusive must be > 0");
  const maxUint32 = 0xffffffff;
  const threshold = maxUint32 - (maxUint32 % maxExclusive);
  const array = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(array);
    const random = array[0];
    if (random < threshold) {
      return random % maxExclusive;
    }
  }
}

function generateRandomPassword(length, charset) {
  if (!charset.length) throw new Error("Empty charset");
  let result = "";
  for (let i = 0; i < length; i++) {
    const idx = cryptoRandomInt(charset.length);
    result += charset[idx];
  }
  return result;
}

function setupRandomGenerator() {
  const lengthSlider = $("#random-length");
  const lengthValue = $("#random-length-value");
  const lowerCb = $("#charset-lower");
  const upperCb = $("#charset-upper");
  const digitsCb = $("#charset-digits");
  const symbolsCb = $("#charset-symbols");
  const generateBtn = $("#generate-random-btn");
  const output = $("#random-output");
  const entropyOut = $("#random-entropy-value");
  const copyBtn = $("#copy-random-btn");

  if (
    !lengthSlider ||
    !lengthValue ||
    !lowerCb ||
    !upperCb ||
    !digitsCb ||
    !symbolsCb ||
    !generateBtn ||
    !output ||
    !entropyOut ||
    !copyBtn
  ) {
    return;
  }

  function updateLengthLabel() {
    lengthValue.textContent = lengthSlider.value;
  }

  lengthSlider.addEventListener("input", updateLengthLabel);
  updateLengthLabel();

  function runGeneration() {
    const length = parseInt(lengthSlider.value, 10) || 16;
    let charset = "";
    if (lowerCb.checked) charset += "abcdefghijklmnopqrstuvwxyz";
    if (upperCb.checked) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (digitsCb.checked) charset += "0123456789";
    if (symbolsCb.checked) charset += "!@#$%^&*()-_=+[]{};:,.?/\\|`~";

    if (!charset) {
      output.value = "";
      entropyOut.textContent = "Select at least one character set.";
      return;
    }

    const pwd = generateRandomPassword(length, charset);
    output.value = pwd;

    const bits = length * log2(charset.length);
    entropyOut.textContent = `${bits.toFixed(1)} bits (charset=${charset.length})`;
  }

  generateBtn.addEventListener("click", runGeneration);

  copyBtn.addEventListener("click", async () => {
    if (!output.value) return;
    try {
      await navigator.clipboard.writeText(output.value);
      copyBtn.textContent = "Copied";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1400);
    } catch {
      copyBtn.textContent = "Copy failed";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1400);
    }
  });
}

const DEMO_DICEWARE_WORDS = [
  "orbit",
  "velvet",
  "harbor",
  "copper",
  "lantern",
  "thistle",
  "marble",
  "ember",
  "linen",
  "compass",
  "juniper",
  "anchor",
  "prairie",
  "citron",
  "hazel",
  "meadow",
  "pixel",
  "sage",
  "avocado",
  "rocket",
  "harvest",
  "violet",
  "ginger",
  "quartz",
];

function generateDiceware(count) {
  const words = [];
  for (let i = 0; i < count; i++) {
    const idx = cryptoRandomInt(DEMO_DICEWARE_WORDS.length);
    words.push(DEMO_DICEWARE_WORDS[idx]);
  }
  return words.join(" ");
}

function setupDicewareGenerator() {
  const countSlider = $("#diceware-count");
  const countValue = $("#diceware-count-value");
  const output = $("#diceware-output");
  const entropyOut = $("#diceware-entropy-value");
  const copyBtn = $("#copy-diceware-btn");
  const generateBtn = $("#generate-diceware-btn");

  if (
    !countSlider ||
    !countValue ||
    !output ||
    !entropyOut ||
    !copyBtn ||
    !generateBtn
  ) {
    return;
  }

  function updateLabel() {
    countValue.textContent = countSlider.value;
  }

  countSlider.addEventListener("input", updateLabel);
  updateLabel();

  function runGeneration() {
    const count = parseInt(countSlider.value, 10) || 6;
    const phrase = generateDiceware(count);
    output.value = phrase;
    const entropyPerWord = 12.9;
    const bits = entropyPerWord * count;
    entropyOut.textContent = `${bits.toFixed(1)} bits (approx. Diceware)`;
  }

  generateBtn.addEventListener("click", runGeneration);

  copyBtn.addEventListener("click", async () => {
    if (!output.value) return;
    try {
      await navigator.clipboard.writeText(output.value);
      copyBtn.textContent = "Copied";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1400);
    } catch {
      copyBtn.textContent = "Copy failed";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1400);
    }
  });
}

function setupTabs() {
  const randomBtn = $("#tab-random-btn");
  const dicewareBtn = $("#tab-diceware-btn");
  const randomPanel = $("#tab-random");
  const dicewarePanel = $("#tab-diceware");

  if (!randomBtn || !dicewareBtn || !randomPanel || !dicewarePanel) return;

  function activate(tab) {
    const isRandom = tab === "random";
    randomBtn.classList.toggle("active", isRandom);
    dicewareBtn.classList.toggle("active", !isRandom);

    randomBtn.setAttribute("aria-selected", String(isRandom));
    dicewareBtn.setAttribute("aria-selected", String(!isRandom));

    randomPanel.hidden = !isRandom;
    dicewarePanel.hidden = isRandom;
  }

  randomBtn.addEventListener("click", () => activate("random"));
  dicewareBtn.addEventListener("click", () => activate("diceware"));
}

window.addEventListener("DOMContentLoaded", () => {
  setupNavScrolling();
  setupStrengthLab();
  setupBreachChecker();
  setupRandomGenerator();
  setupDicewareGenerator();
  setupTabs();
});

