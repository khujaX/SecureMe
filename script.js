// SecureMe - Frontend Only (No Functionality)
// This is a UI mockup demonstrating the frontend design only.

const $ = (selector) => document.querySelector(selector);

// Basic smooth scrolling for navigation
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

// Tab switching (UI only)
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

// Password visibility toggle (UI only)
function setupPasswordVisibilityToggle() {
  const input = $("#password-input");
  const toggleBtn = $("#toggle-password-visibility");

  if (!input || !toggleBtn) return;

  toggleBtn.addEventListener("click", () => {
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.textContent = isPassword ? "Hide" : "Show";
    toggleBtn.setAttribute("aria-pressed", String(isPassword));
    toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });
}

// Slider label updates (UI only)
function setupSliders() {
  const lengthSlider = $("#random-length");
  const lengthValue = $("#random-length-value");
  const countSlider = $("#diceware-count");
  const countValue = $("#diceware-count-value");

  if (lengthSlider && lengthValue) {
    function updateLengthLabel() {
      lengthValue.textContent = lengthSlider.value;
    }
    lengthSlider.addEventListener("input", updateLengthLabel);
    updateLengthLabel();
  }

  if (countSlider && countValue) {
    function updateCountLabel() {
      countValue.textContent = countSlider.value;
    }
    countSlider.addEventListener("input", updateCountLabel);
    updateCountLabel();
  }
}

// Disable all functional buttons and show placeholder messages
function setupPlaceholderButtons() {
  // Strength lab - show placeholder message
  const strengthInput = $("#password-input");
  const strengthFeedback = $("#strength-summary");
  
  if (strengthInput && strengthFeedback) {
    strengthInput.addEventListener("input", () => {
      strengthFeedback.textContent = "Functionality not implemented yet.";
    });
  }

  // Breach checker button
  const breachBtn = $("#breach-check-btn");
  const breachStatus = $("#breach-status");
  
  if (breachBtn && breachStatus) {
    breachBtn.addEventListener("click", () => {
      breachStatus.textContent = "Functionality not implemented yet.";
    });
  }

  // Password generators
  const generateRandomBtn = $("#generate-random-btn");
  const randomOutput = $("#random-output");
  const randomEntropy = $("#random-entropy-value");
  
  if (generateRandomBtn) {
    generateRandomBtn.addEventListener("click", () => {
      if (randomOutput) randomOutput.value = "";
      if (randomEntropy) randomEntropy.textContent = "Functionality not implemented yet.";
    });
  }

  const generateDicewareBtn = $("#generate-diceware-btn");
  const dicewareOutput = $("#diceware-output");
  const dicewareEntropy = $("#diceware-entropy-value");
  
  if (generateDicewareBtn) {
    generateDicewareBtn.addEventListener("click", () => {
      if (dicewareOutput) dicewareOutput.value = "";
      if (dicewareEntropy) dicewareEntropy.textContent = "Functionality not implemented yet.";
    });
  }

  // Copy buttons
  const copyButtons = document.querySelectorAll("[id$='-btn'][id^='copy-']");
  copyButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const originalText = btn.textContent;
      btn.textContent = "Functionality not implemented yet.";
      setTimeout(() => {
        btn.textContent = originalText;
      }, 2000);
    });
  });
}

// Initialize on page load
window.addEventListener("DOMContentLoaded", () => {
  setupNavScrolling();
  setupTabs();
  setupPasswordVisibilityToggle();
  setupSliders();
  setupPlaceholderButtons();
});
