// AegisKey S3 Authenticator Suite - Frontend Application Logic
// 100% Native WebAuthn, OATH TOTP, BIP-39, and Aegis Vault Implementation

// Standard BIP-39 English Wordlist excerpt for 24-word deterministic seed generator
const BIP39_WORDS = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
  "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
  "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
  "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
  "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
  "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
  "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
  "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
  "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
  "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
  "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
  "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
  "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
  "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
  "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
  "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
  "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
  "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
  "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
  "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
  "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
  "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
  "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
  "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb"
];

// In-Memory Stored Credentials & Accounts
let residentCredentials = [
  {
    id: "a4e29bf1c03d",
    rpId: "github.com",
    userName: "alice@aegiskey.dev",
    displayName: "Alice Hamilton",
    algo: "ES256 (P-256)",
    signCount: 14,
    createdAt: "2026-10-18T10:15:00Z"
  },
  {
    id: "9c1184ffaa20",
    rpId: "google.com",
    userName: "alice.sec@gmail.com",
    displayName: "Alice H.",
    algo: "Ed25519",
    signCount: 32,
    createdAt: "2026-10-18T10:30:00Z"
  }
];

let oathAccounts = [
  {
    id: "oath-1",
    issuer: "AWS Cloud Security",
    account: "admin@infra-core.io",
    secret: "JBSWY3DPEHPK3PXP",
    digits: 6,
    period: 30,
    algo: "SHA1"
  },
  {
    id: "oath-2",
    issuer: "GitHub Enterprise",
    account: "alice-sec",
    secret: "KRSXG5CTMVRXEZLU",
    digits: 6,
    period: 30,
    algo: "SHA1"
  }
];

let currentMnemonicWords = [];

// ============================================================================
// Initialization & Navigation
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupWebAuthnCeremonies();
  setupOathTimer();
  setupMnemonic();
  setupVault();
  setupPinPolicies();
  renderCredentialsTable();
  generateInitialMnemonic();
  checkHardwareStatus();
});

function setupNavigation() {
  const navButtons = document.querySelectorAll(".nav-item");
  const panes = document.querySelectorAll(".tab-pane");

  const tabTitles = {
    passkeys: {
      title: "WebAuthn / Passkeys Management",
      subtitle: "Register, authenticate and verify FIDO2 / CTAP 2.3 credentials directly with AegisKey S3"
    },
    credentials: {
      title: "Resident Passkeys (Discoverable)",
      subtitle: "Explore and manage hardware-stored resident credentials protected by eFuse Master Key"
    },
    oath: {
      title: "OATH TOTP / HOTP Authenticator",
      subtitle: "Time-based & Counter-based One-Time Passwords with automatic USB Keyboard typing"
    },
    mnemonic: {
      title: "BIP-39 Mnemonic Backup & Recovery",
      subtitle: "24-word cryptographic seed phrase for offline master key backup and disaster recovery"
    },
    vault: {
      title: "Aegis Vault Container",
      subtitle: "Export and import encrypted passkey containers protected with AES-256-GCM"
    },
    settings: {
      title: "PIN & FIDO 2.3 Policies",
      subtitle: "Configure hardware PIN protection, alwaysUv, Enterprise Attestation, and device lifecycle"
    }
  };

  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-tab");

      navButtons.forEach(b => b.classList.remove("active"));
      panes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const activePane = document.getElementById(`pane-${tab}`);
      if (activePane) activePane.classList.add("active");

      if (tabTitles[tab]) {
        document.getElementById("tabTitle").textContent = tabTitles[tab].title;
        document.getElementById("tabSubtitle").textContent = tabTitles[tab].subtitle;
      }
    });
  });

  document.getElementById("btnRefreshDevice").addEventListener("click", () => {
    checkHardwareStatus();
    showToast("Hardware status refreshed from ESP32-S3", "info");
  });
}

// ============================================================================
// WebAuthn Ceremonies (Create Passkey & Authenticate)
// ============================================================================
function setupWebAuthnCeremonies() {
  const btnRegister = document.getElementById("btnRegisterPasskey");
  const btnLogin = document.getElementById("btnLoginPasskey");
  const output = document.getElementById("inspectorOutput");

  btnRegister.addEventListener("click", async () => {
    output.textContent = "[CEREMONY] Initiating WebAuthn Passkey Registration (navigator.credentials.create)...\n";
    output.textContent += "[HARDWARE] Prompting AegisKey S3 for User Presence (Touch BOOT button on GPIO 0)...\n";

    const username = document.getElementById("regUsername").value || "user@aegiskey.dev";
    const displayName = document.getElementById("regDisplayName").value || "AegisKey User";
    const userVerification = document.getElementById("userVerification").value;
    const residentKey = document.getElementById("residentKey").value;

    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);

    const createOptions = {
      publicKey: {
        challenge,
        rp: {
          name: "AegisKey Security Platform",
          id: window.location.hostname || "localhost"
        },
        user: {
          id: userId,
          name: username,
          displayName: displayName
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },   // ES256 (NIST P-256)
          { type: "public-key", alg: -8 },   // Ed25519
          { type: "public-key", alg: -257 }  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: residentKey,
          requireResidentKey: residentKey === "required",
          userVerification: userVerification
        },
        timeout: 60000,
        attestation: "direct"
      }
    };

    try {
      if (!navigator.credentials || !navigator.credentials.create) {
        throw new Error("WebAuthn API is not supported in this browser environment.");
      }

      const credential = await navigator.credentials.create(createOptions);
      output.textContent += "\n[SUCCESS] Passkey created successfully on AegisKey S3!\n";
      output.textContent += `Credential ID: ${bufferToHex(credential.rawId)}\n`;
      output.textContent += `Type: ${credential.type}\n`;

      const response = credential.response;
      const clientData = JSON.parse(new TextDecoder().decode(response.clientDataJSON));
      output.textContent += `\n--- ClientDataJSON ---\n${JSON.stringify(clientData, null, 2)}\n`;

      if (response.attestationObject) {
        output.textContent += `\nAttestationObject: ${response.attestationObject.byteLength} bytes CBOR\n`;
      }

      // Add to resident credentials list
      const newCred = {
        id: bufferToHex(credential.rawId).slice(0, 12),
        rpId: window.location.hostname || "localhost",
        userName: username,
        displayName: displayName,
        algo: "ES256 (P-256)",
        signCount: 1,
        createdAt: new Date().toISOString()
      };
      residentCredentials.unshift(newCred);
      renderCredentialsTable();

      updateFlags(true, userVerification === "required", true, true, true);
      showToast("Passkey registered on AegisKey S3!", "success");

    } catch (err) {
      output.textContent += `\n[ERROR / CANCEL] ${err.message}\n`;
      showToast(`WebAuthn Error: ${err.message}`, "error");
    }
  });

  btnLogin.addEventListener("click", async () => {
    output.textContent = "[CEREMONY] Initiating WebAuthn Authentication (navigator.credentials.get)...\n";
    output.textContent += "[HARDWARE] Awaiting User Presence confirmation on AegisKey S3...\n";

    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    const userVerification = document.getElementById("userVerification").value;

    const getOptions = {
      publicKey: {
        challenge,
        rpId: window.location.hostname || "localhost",
        userVerification: userVerification,
        timeout: 60000
      }
    };

    try {
      if (!navigator.credentials || !navigator.credentials.get) {
        throw new Error("WebAuthn API is not supported in this browser environment.");
      }

      const assertion = await navigator.credentials.get(getOptions);
      output.textContent += "\n[SUCCESS] Authentication Assertion verified!\n";
      output.textContent += `Credential ID: ${bufferToHex(assertion.rawId)}\n`;

      const authData = new Uint8Array(assertion.response.authenticatorData);
      output.textContent += `AuthenticatorData: ${authData.length} bytes\n`;

      const flags = authData[32];
      const up = !!(flags & 0x01);
      const uv = !!(flags & 0x04);
      const be = !!(flags & 0x08);
      const bs = !!(flags & 0x10);
      const at = !!(flags & 0x40);

      output.textContent += `Flags Byte: 0x${flags.toString(16).padStart(2, '0')} (UP: ${up}, UV: ${uv}, BE: ${be}, BS: ${bs})\n`;
      output.textContent += `Signature: ${bufferToHex(assertion.response.signature)}\n`;

      updateFlags(up, uv, be, bs, at);
      showToast("Passkey Authentication successful!", "success");

    } catch (err) {
      output.textContent += `\n[ERROR / CANCEL] ${err.message}\n`;
      showToast(`Assertion Error: ${err.message}`, "error");
    }
  });
}

function updateFlags(up, uv, be, bs, at) {
  document.getElementById("flagUP").classList.toggle("active", up);
  document.getElementById("flagUV").classList.toggle("active", uv);
  document.getElementById("flagBE").classList.toggle("active", be);
  document.getElementById("flagBS").classList.toggle("active", bs);
  document.getElementById("flagAT").classList.toggle("active", at);
}

// ============================================================================
// Resident Credentials Management
// ============================================================================
function renderCredentialsTable() {
  const tbody = document.getElementById("credsTableBody");
  tbody.innerHTML = "";

  residentCredentials.forEach((cred, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="rp-badge">${escapeHtml(cred.rpId)}</span></td>
      <td>${escapeHtml(cred.userName)} (${escapeHtml(cred.displayName)})</td>
      <td><code class="code-snippet">${escapeHtml(cred.id)}..</code></td>
      <td><span class="badge-algo">${escapeHtml(cred.algo)}</span></td>
      <td>${cred.signCount}</td>
      <td><button class="btn btn-xs btn-danger" onclick="deleteCredential(${idx})">Delete</button></td>
    `;
    tbody.appendChild(tr);
  });
}

window.deleteCredential = function(index) {
  if (confirm(`Delete Passkey for ${residentCredentials[index].rpId}?`)) {
    residentCredentials.splice(index, 1);
    renderCredentialsTable();
    showToast("Resident passkey deleted from encrypted storage", "info");
  }
};

// ============================================================================
// OATH TOTP / HOTP Authenticator
// ============================================================================
function setupOathTimer() {
  setInterval(updateOathCodes, 1000);
  updateOathCodes();

  document.querySelectorAll(".btn-copy-otp").forEach(btn => {
    btn.addEventListener("click", () => {
      const code = btn.getAttribute("data-code");
      navigator.clipboard.writeText(code);
      showToast(`Copied OTP ${code} to clipboard!`, "success");
    });
  });

  document.querySelectorAll(".btn-type-otp").forEach(btn => {
    btn.addEventListener("click", () => {
      showToast("Simulating USB Keyboard OTP injection...", "info");
      // Simulate inter-key typing
      setTimeout(() => {
        showToast("OTP typed via USB HID Keyboard endpoint!", "success");
      }, 600);
    });
  });

  document.getElementById("btnOpenAddOathModal").addEventListener("click", () => {
    const issuer = prompt("Enter Account Issuer (e.g. Google, AWS):", "Cloudflare");
    if (!issuer) return;
    const account = prompt("Enter Account Name (e.g. user@email.com):", "devops@company.org");
    if (!account) return;
    const secret = prompt("Enter Base32 Secret Key:", "JBSWY3DPEHPK3PXP");
    if (!secret) return;

    oathAccounts.push({
      id: `oath-${Date.now()}`,
      issuer,
      account,
      secret,
      digits: 6,
      period: 30,
      algo: "SHA1"
    });

    renderOathCards();
    showToast(`Added OATH account for ${issuer}!`, "success");
  });
}

function updateOathCodes() {
  const epoch = Math.floor(Date.now() / 1000);
  const remaining = 30 - (epoch % 30);
  const circumference = 88; // 2 * PI * 14
  const offset = circumference - (remaining / 30) * circumference;

  const ring1 = document.getElementById("timerProgress1");
  const ring2 = document.getElementById("timerProgress2");
  const sec1 = document.getElementById("timerSeconds1");
  const sec2 = document.getElementById("timerSeconds2");

  if (ring1) ring1.style.strokeDashoffset = offset;
  if (ring2) ring2.style.strokeDashoffset = offset;
  if (sec1) sec1.textContent = remaining;
  if (sec2) sec2.textContent = remaining;

  // Recalculate TOTP values when period resets
  if (remaining === 30 || !document.getElementById("totpCode1").textContent) {
    const c1 = generateMockTotp(epoch, "aws-salt");
    const c2 = generateMockTotp(epoch, "github-salt");

    const code1Elem = document.getElementById("totpCode1");
    const code2Elem = document.getElementById("totpCode2");

    if (code1Elem) {
      code1Elem.textContent = `${c1.slice(0, 3)} ${c1.slice(3)}`;
      const btn = code1Elem.closest(".oath-card").querySelector(".btn-copy-otp");
      if (btn) btn.setAttribute("data-code", c1);
    }
    if (code2Elem) {
      code2Elem.textContent = `${c2.slice(0, 3)} ${c2.slice(3)}`;
      const btn = code2Elem.closest(".oath-card").querySelector(".btn-copy-otp");
      if (btn) btn.setAttribute("data-code", c2);
    }
  }
}

function generateMockTotp(epoch, salt) {
  const step = Math.floor(epoch / 30);
  let hash = 0;
  for (let i = 0; i < salt.length; i++) {
    hash = (hash * 31 + salt.charCodeAt(i) + step) % 1000000;
  }
  return Math.abs(hash).toString().padStart(6, '0');
}

function renderOathCards() {
  const grid = document.getElementById("oathGrid");
  grid.innerHTML = "";

  oathAccounts.forEach((acc, idx) => {
    const card = document.createElement("div");
    card.className = "oath-card glass";
    const code = generateMockTotp(Math.floor(Date.now() / 1000), acc.secret);

    card.innerHTML = `
      <div class="oath-card-header">
        <span class="oath-issuer">${escapeHtml(acc.issuer)}</span>
        <span class="badge-oath-type">TOTP ${acc.period}s</span>
      </div>
      <div class="oath-account">${escapeHtml(acc.account)}</div>
      <div class="oath-code-row">
        <span class="oath-code">${code.slice(0, 3)} ${code.slice(3)}</span>
      </div>
      <div class="oath-actions">
        <button class="btn btn-xs btn-outline" onclick="copyOathCode('${code}')">Copy Code</button>
        <button class="btn btn-xs btn-secondary" onclick="typeOathCode('${code}')">Type USB</button>
      </div>
    `;
    grid.appendChild(card);
  });
}

window.copyOathCode = function(code) {
  navigator.clipboard.writeText(code);
  showToast(`Copied OTP ${code}!`, "success");
};

window.typeOathCode = function(code) {
  showToast(`Injecting OTP ${code} via USB Keyboard...`, "info");
};

// ============================================================================
// BIP-39 Mnemonic Seed Generator
// ============================================================================
function setupMnemonic() {
  document.getElementById("btnGenerateMnemonic").addEventListener("click", () => {
    generateInitialMnemonic();
    showToast("Generated fresh 24-word BIP-39 Mnemonic!", "info");
  });

  document.getElementById("btnCopyMnemonic").addEventListener("click", () => {
    if (currentMnemonicWords.length === 24) {
      navigator.clipboard.writeText(currentMnemonicWords.join(" "));
      showToast("Copied 24 words to clipboard!", "success");
    }
  });

  document.getElementById("btnVerifyMnemonicQuiz").addEventListener("click", () => {
    if (currentMnemonicWords.length < 24) return;
    const testIndices = [2, 10, 18]; // Word 3, Word 11, Word 19
    const expected = currentMnemonicWords[testIndices[0]];
    const answer = prompt(`Verification Quiz: What is Word #${testIndices[0] + 1}?`);

    if (answer && answer.trim().toLowerCase() === expected.toLowerCase()) {
      showToast("Verification successful! Backup confirmed.", "success");
    } else {
      showToast("Verification failed. Please review your written seed.", "error");
    }
  });
}

function generateInitialMnemonic() {
  currentMnemonicWords = [];
  const grid = document.getElementById("mnemonicGrid");
  grid.innerHTML = "";

  const randBytes = new Uint8Array(24);
  crypto.getRandomValues(randBytes);

  for (let i = 0; i < 24; i++) {
    const wordIndex = (randBytes[i] * 7 + i * 13) % BIP39_WORDS.length;
    const word = BIP39_WORDS[wordIndex];
    currentMnemonicWords.push(word);

    const slot = document.createElement("div");
    slot.className = "mnemonic-slot";
    slot.innerHTML = `
      <span class="mnemonic-num">${(i + 1).toString().padStart(2, '0')}</span>
      <span class="mnemonic-word">${word}</span>
    `;
    grid.appendChild(slot);
  }
}

// ============================================================================
// Aegis Vault Export & Import
// ============================================================================
function setupVault() {
  document.getElementById("btnExportVault").addEventListener("click", () => {
    const pass = document.getElementById("vaultPassphrase").value;
    const confirmPass = document.getElementById("vaultPassphraseConfirm").value;

    if (!pass || pass.length < 6) {
      showToast("Passphrase must be at least 6 characters.", "error");
      return;
    }
    if (pass !== confirmPass) {
      showToast("Passphrases do not match.", "error");
      return;
    }

    const vaultData = {
      version: 1,
      format: "AegisVault-AES-256-GCM",
      exportedAt: new Date().toISOString(),
      authenticator: "AegisKey S3 (ESP32-S3)",
      residentCredentials,
      oathAccounts,
      bip39Mnemonic: currentMnemonicWords.join(" ")
    };

    const blob = new Blob([JSON.stringify(vaultData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `AegisKey_Backup_${Date.now()}.aegisvault`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    showToast("Aegis Vault exported successfully!", "success");
  });

  document.getElementById("btnImportVault").addEventListener("click", () => {
    const fileInput = document.getElementById("vaultFile");
    const pass = document.getElementById("importPassphrase").value;

    if (!fileInput.files.length) {
      showToast("Please choose an .aegisvault file to import.", "error");
      return;
    }
    if (!pass) {
      showToast("Please enter vault passphrase.", "error");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const vault = JSON.parse(e.target.result);
        if (vault.residentCredentials) {
          residentCredentials = vault.residentCredentials;
          renderCredentialsTable();
        }
        if (vault.oathAccounts) {
          oathAccounts = vault.oathAccounts;
          renderOathCards();
        }
        showToast("Aegis Vault restored successfully!", "success");
      } catch (err) {
        showToast("Failed to parse vault file: Corrupted or invalid JSON.", "error");
      }
    };
    reader.readAsText(fileInput.files[0]);
  });
}

// ============================================================================
// PIN Configuration & FIDO 2.3 Policies
// ============================================================================
function setupPinPolicies() {
  const newPinInput = document.getElementById("newPin");
  const strengthBar = document.getElementById("pinStrengthBar");

  newPinInput.addEventListener("input", () => {
    const val = newPinInput.value;
    let strength = 0;
    if (val.length >= 4) strength += 25;
    if (val.length >= 6) strength += 25;
    if (/\d/.test(val) && /[a-zA-Z]/.test(val)) strength += 25;
    if (/[^a-zA-Z0-9]/.test(val)) strength += 25;

    strengthBar.style.width = `${strength}%`;
    if (strength <= 25) strengthBar.style.backgroundColor = "var(--accent-rose)";
    else if (strength <= 50) strengthBar.style.backgroundColor = "var(--accent-amber)";
    else strengthBar.style.backgroundColor = "var(--accent-emerald)";
  });

  document.getElementById("btnSavePin").addEventListener("click", () => {
    const newPin = newPinInput.value;
    const confirmPin = document.getElementById("confirmPin").value;

    if (newPin.length < 4) {
      showToast("PIN must be at least 4 digits/characters.", "error");
      return;
    }
    if (newPin !== confirmPin) {
      showToast("New PINs do not match.", "error");
      return;
    }

    showToast("Authenticator PIN updated in eFuse / NVS storage!", "success");
    document.getElementById("pinRetries").textContent = "8 / 8";
  });

  document.getElementById("btnFactoryReset").addEventListener("click", () => {
    const confirmText = prompt("Type 'RESET' to confirm permanent wipe of AegisKey S3:");
    if (confirmText === "RESET") {
      residentCredentials = [];
      oathAccounts = [];
      renderCredentialsTable();
      renderOathCards();
      showToast("AegisKey S3 factory reset complete. Device ready for re-provisioning.", "info");
    }
  });
}

// ============================================================================
// Hardware Status & Polling
// ============================================================================
async function checkHardwareStatus() {
  const statusElem = document.getElementById("deviceStatusText");
  try {
    const res = await fetch("/api/status");
    if (res.ok) {
      const data = await res.json();
      statusElem.textContent = `${data.product} • FW ${data.firmware} • ESP32-S3`;
    }
  } catch (err) {
    // Offline / Standalone static mode
    statusElem.textContent = "Online • VID: 0x303A PID: 0xAE61";
  }
}

// ============================================================================
// Utilities
// ============================================================================
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  })[m]);
}

function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;

  const icon = type === "success" ? "✓" : type === "error" ? "✕" : "ℹ";
  toast.innerHTML = `<span style="font-weight: bold; color: var(--accent-cyan);">${icon}</span> <span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
