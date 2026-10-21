const MAX_RECENT_ENTRIES = 10;

const state = {
  issuer: null,
  head: null,
  latestCredential: null,
  proofs: new Map(),
  selectedIndex: null,
  selectedProof: null,
};

const $ = (id) => document.getElementById(id);
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function setConnection(status, label) {
  const element = $("connection");
  element.dataset.state = status;
  $("connectionText").textContent = label;
}

function showError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.hidden = false;
}

function clearError(id) {
  const element = $(id);
  element.textContent = "";
  element.hidden = true;
}

function formatTime(seconds) {
  if (!Number.isFinite(seconds)) {
    return "—";
  }
  return dateFormat.format(new Date(seconds * 1000));
}

function shortHash(value, length = 16) {
  if (typeof value !== "string") {
    return "—";
  }
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function setBusy(button, busy, label) {
  if (busy) {
    button.dataset.idleLabel = button.textContent;
    button.textContent = label;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.idleLabel || button.textContent;
    button.disabled = false;
    delete button.dataset.idleLabel;
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error(`Request failed with status ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(body?.error?.message || `Request failed with status ${response.status}`);
  }
  return body;
}

async function refreshOverview({ quiet = false } = {}) {
  try {
    const [issuer, head] = await Promise.all([api("/v1/issuer"), api("/v1/log")]);
    state.issuer = issuer;
    state.head = head;
    $("issuerId").textContent = issuer.issuer;
    $("issuerId").title = issuer.issuer;
    $("keyId").textContent = issuer.key_id;
    $("keyId").title = issuer.key_id;
    $("treeSize").textContent = String(head.tree_size);
    $("rootHash").textContent = head.root_hash;
    $("rootHash").title = head.root_hash;
    setConnection("online", "Online");
    return true;
  } catch (error) {
    setConnection("offline", "Offline");
    if (!quiet) {
      showError("issueError", error.message);
    }
    return false;
  }
}

function renderEntriesMessage(message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty";
  cell.textContent = message;
  row.append(cell);
  $("entriesBody").replaceChildren(row);
}

function buildEntryRow(proof) {
  const index = proof.entry.index;
  const row = document.createElement("tr");
  row.dataset.index = String(index);
  row.dataset.selected = String(state.selectedIndex === index);

  const indexCell = document.createElement("td");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "row-button";
  button.textContent = String(index);
  button.setAttribute("aria-label", `Show inclusion proof for log entry ${index}`);
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    selectProof(index);
  });
  indexCell.append(button);

  const subjectCell = document.createElement("td");
  const subjectCode = document.createElement("code");
  subjectCode.textContent = shortHash(proof.entry.subject_hash);
  subjectCode.title = proof.entry.subject_hash;
  subjectCell.append(subjectCode);

  const issuedCell = document.createElement("td");
  issuedCell.textContent = formatTime(proof.entry.issued_at);

  const expiresCell = document.createElement("td");
  expiresCell.textContent = formatTime(proof.entry.expires_at);

  row.append(indexCell, subjectCell, issuedCell, expiresCell);
  row.addEventListener("click", () => selectProof(index));
  return row;
}

async function loadEntries() {
  if (!state.head && !(await refreshOverview({ quiet: true }))) {
    renderEntriesMessage("Cannot reach the service.");
    return;
  }

  const size = state.head.tree_size;
  if (size === 0) {
    renderEntriesMessage("No entries yet. Issue a credential to start the log.");
    clearProof();
    return;
  }

  const start = Math.max(0, size - MAX_RECENT_ENTRIES);
  const indexes = [];
  for (let index = start; index < size; index += 1) {
    indexes.push(index);
  }

  try {
    const proofs = await Promise.all(indexes.map((index) => api(`/v1/log/entries/${index}`)));
    state.proofs = new Map(proofs.map((proof) => [proof.entry.index, proof]));
    const body = $("entriesBody");
    body.replaceChildren();
    proofs
      .slice()
      .reverse()
      .forEach((proof) => body.append(buildEntryRow(proof)));

    if (state.selectedIndex !== null && state.proofs.has(state.selectedIndex)) {
      showProof(state.proofs.get(state.selectedIndex));
    } else {
      clearProof();
    }
  } catch (error) {
    renderEntriesMessage(error.message);
  }
}

function clearProof() {
  state.selectedIndex = null;
  state.selectedProof = null;
  $("proofEmpty").hidden = false;
  $("proofEmptyText").textContent = "Select a log entry to see the path to the signed tree head.";
  $("proofContent").hidden = true;
  $("localCheck").hidden = true;
  document.querySelectorAll("#entriesBody tr[data-index]").forEach((row) => {
    row.dataset.selected = "false";
  });
}

function showProof(proof, updateSelection = true) {
  if (updateSelection) {
    state.selectedIndex = proof.entry.index;
  }
  state.selectedProof = proof;
  $("proofEmpty").hidden = true;
  $("proofContent").hidden = false;
  $("proofTitle").textContent = `Entry ${proof.entry.index}`;
  $("proofIndex").textContent = String(proof.entry.index);
  $("proofLeaf").textContent = shortHash(proof.leaf_hash, 20);
  $("proofLeaf").title = proof.leaf_hash;
  $("proofRoot").textContent = shortHash(proof.tree_head.root_hash, 20);
  $("proofRoot").title = proof.tree_head.root_hash;
  $("proofTreeSize").textContent = String(proof.tree_head.tree_size);
  $("proofBody").textContent = JSON.stringify(proof, null, 2);
  $("localCheck").hidden = true;
  $("localCheck").textContent = "";
  $("localCheck").removeAttribute("data-state");
  document.querySelectorAll("#entriesBody tr[data-index]").forEach((row) => {
    row.dataset.selected = String(Number(row.dataset.index) === proof.entry.index);
  });
}

async function selectProof(index) {
  try {
    const proof = state.proofs.get(index) ?? (await api(`/v1/log/entries/${index}`));
    showProof(proof);
  } catch (error) {
    $("proofEmpty").hidden = false;
    $("proofContent").hidden = true;
    $("proofEmptyText").textContent = error.message;
  }
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function fromBase64Url(value) {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBase64Url(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  parts.forEach((part) => {
    result.set(part, offset);
    offset += part.length;
  });
  return result;
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function hashLeaf(entry) {
  const payload = new TextEncoder().encode(canonicalize(entry));
  return digest(concatBytes(Uint8Array.of(0), payload));
}

async function hashNode(left, right) {
  return digest(concatBytes(Uint8Array.of(1), left, right));
}

async function inclusionRoot(index, size, leaf, proof) {
  let leafIndex = Number(index);
  let lastIndex = Number(size) - 1;
  let root = leaf;

  for (const sibling of proof) {
    if (lastIndex === 0) {
      throw new Error("proof extends past the tree");
    }
    if (leafIndex % 2 === 1 || leafIndex === lastIndex) {
      root = await hashNode(sibling, root);
      while (leafIndex % 2 === 0 && leafIndex !== 0) {
        leafIndex = Math.floor(leafIndex / 2);
        lastIndex = Math.floor(lastIndex / 2);
      }
    } else {
      root = await hashNode(root, sibling);
    }
    leafIndex = Math.floor(leafIndex / 2);
    lastIndex = Math.floor(lastIndex / 2);
  }

  if (lastIndex !== 0) {
    throw new Error("proof ends before the root");
  }
  return root;
}

async function verifyTreeHeadSignature(head, publicKey) {
  if (!globalThis.crypto?.subtle) {
    return "unsupported";
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      fromBase64Url(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const payload = new TextEncoder().encode(
      canonicalize({ tree_size: head.tree_size, root_hash: head.root_hash }),
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      fromBase64Url(head.signature),
      payload,
    );
    return valid ? "valid" : "invalid";
  } catch {
    return "unsupported";
  }
}

async function checkProofLocally() {
  const proof = state.selectedProof;
  const result = $("localCheck");
  result.hidden = false;
  result.dataset.state = "pending";
  result.textContent = "Checking inclusion path…";

  try {
    const leaf = await hashLeaf(proof.entry);
    const leafMatches = toBase64Url(leaf) === proof.leaf_hash;
    if (!leafMatches) {
      result.dataset.state = "bad";
      result.textContent = "Leaf hash does not match the entry. Proof rejected.";
      return;
    }

    const root = await inclusionRoot(
      proof.entry.index,
      proof.tree_head.tree_size,
      leaf,
      proof.inclusion_proof.map(fromBase64Url),
    );
    const rootMatches = toBase64Url(root) === proof.tree_head.root_hash;
    if (!rootMatches) {
      result.dataset.state = "bad";
      result.textContent = "Inclusion path does not reach the signed root. Proof rejected.";
      return;
    }

    const keyMatches = state.issuer && proof.tree_head.key_id === state.issuer.key_id;
    const signature = keyMatches
      ? await verifyTreeHeadSignature(proof.tree_head, state.issuer.public_key)
      : "mismatch";

    if (signature === "valid") {
      result.dataset.state = "ok";
      result.textContent = "Inclusion and tree-head signature verified locally.";
    } else if (signature === "unsupported") {
      result.dataset.state = "ok";
      result.textContent =
        "Inclusion verified locally. This browser cannot verify Ed25519 tree-head signatures.";
    } else if (signature === "mismatch") {
      result.dataset.state = "bad";
      result.textContent =
        "Inclusion verified, but the tree-head key id does not match the issuer.";
    } else {
      result.dataset.state = "bad";
      result.textContent = "Inclusion verified, but the tree-head signature is invalid.";
    }
  } catch (error) {
    result.dataset.state = "bad";
    result.textContent = `Local check failed: ${error.message}`;
  }
}

async function copyText(text, button, label = "Copied") {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = label;
  } catch {
    button.textContent = "Copy failed";
  }
  window.setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

$("issueForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError("issueError");
  $("issueOutcome").hidden = true;

  const subject = $("subject").value.trim();
  let claims;
  try {
    claims = JSON.parse($("claims").value || "{}");
  } catch {
    showError("issueError", "Claims must be valid JSON.");
    return;
  }
  if (!claims || Array.isArray(claims) || typeof claims !== "object") {
    showError("issueError", "Claims must be a JSON object.");
    return;
  }

  const ttl = Number($("ttl").value);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 2592000) {
    showError("issueError", "Lifetime must be an integer between 1 and 2592000 seconds.");
    return;
  }

  const button = $("issueButton");
  setBusy(button, true, "Issuing…");
  try {
    const result = await api("/v1/credentials", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject, claims, ttl_seconds: ttl }),
    });
    state.latestCredential = result.credential;
    $("issuedSubject").textContent = result.credential.subject;
    $("issuedIndex").textContent = String(result.transparency.entry.index);
    $("issuedTreeSize").textContent = String(result.transparency.tree_head.tree_size);
    $("issuedExpiry").textContent = formatTime(result.credential.expires_at);
    $("issuedCredential").textContent = JSON.stringify(result.credential, null, 2);
    $("credential").value = JSON.stringify(result.credential, null, 2);
    $("issueOutcome").hidden = false;

    await refreshOverview({ quiet: true });
    await loadEntries();
    if (state.proofs.has(result.transparency.entry.index)) {
      showProof(state.proofs.get(result.transparency.entry.index));
    }
  } catch (error) {
    showError("issueError", error.message);
  } finally {
    setBusy(button, false);
  }
});

$("verifyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError("verifyError");
  $("verifyOutcome").hidden = true;

  let parsed;
  try {
    parsed = JSON.parse($("credential").value);
  } catch {
    showError("verifyError", "Credential must be valid JSON.");
    return;
  }
  const credential = parsed?.credential ?? parsed;
  if (!credential || typeof credential !== "object" || Array.isArray(credential)) {
    showError("verifyError", "Expected a credential object or an issuance response.");
    return;
  }

  const button = $("verifyButton");
  setBusy(button, true, "Verifying…");
  try {
    const result = await api("/v1/credentials/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential }),
    });
    $("verifyOutcome").hidden = false;
    const verdict = $("verdict");
    if (result.valid) {
      verdict.dataset.valid = "true";
      $("verdictTitle").textContent = "Valid";
      $("verdictReason").textContent = `Signed by ${result.issuer}`;
      $("verifiedFacts").hidden = false;
      $("verifiedSubject").textContent = result.subject;
      $("verifiedIssued").textContent = formatTime(result.issued_at);
      $("verifiedExpiry").textContent = formatTime(result.expires_at);
      $("verifiedKey").textContent = result.key_id;
      $("verifiedClaims").hidden = false;
      $("verifiedClaims").textContent = JSON.stringify(result.claims, null, 2);
    } else {
      verdict.dataset.valid = "false";
      $("verdictTitle").textContent = "Rejected";
      $("verdictReason").textContent = `${result.code}: ${result.reason}`;
      $("verifiedFacts").hidden = true;
      $("verifiedClaims").hidden = true;
    }
  } catch (error) {
    showError("verifyError", error.message);
  } finally {
    setBusy(button, false);
  }
});

$("verifyLatest").addEventListener("click", () => {
  if (state.latestCredential) {
    $("credential").value = JSON.stringify(state.latestCredential, null, 2);
    $("credential").scrollIntoView({
      block: "center",
      behavior: reducedMotion.matches ? "auto" : "smooth",
    });
    $("verifyForm").requestSubmit();
  }
});

$("copyCredential").addEventListener("click", () => {
  if (state.latestCredential) {
    copyText(JSON.stringify(state.latestCredential, null, 2), $("copyCredential"));
  }
});

$("refreshOverview").addEventListener("click", async () => {
  await refreshOverview();
  await loadEntries();
});

$("refreshEntries").addEventListener("click", async () => {
  await refreshOverview({ quiet: true });
  await loadEntries();
});

$("copyProof").addEventListener("click", () => {
  if (state.selectedProof) {
    copyText(JSON.stringify(state.selectedProof, null, 2), $("copyProof"));
  }
});

$("checkProof").addEventListener("click", checkProofLocally);

$("consistencyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError("consistencyError");
  $("consistencyOutput").hidden = true;

  const first = Number($("firstSize").value);
  const second = Number($("secondSize").value);
  if (!Number.isInteger(first) || !Number.isInteger(second) || first < 0 || second < 0) {
    showError("consistencyError", "Sizes must be non-negative integers.");
    return;
  }

  const button = $("consistencyButton");
  setBusy(button, true, "Loading…");
  try {
    const proof = await api(`/v1/log/consistency?first=${first}&second=${second}`);
    $("consistencyOutput").textContent = JSON.stringify(proof, null, 2);
    $("consistencyOutput").hidden = false;
  } catch (error) {
    showError("consistencyError", error.message);
  } finally {
    setBusy(button, false);
  }
});

async function init() {
  const online = await refreshOverview({ quiet: true });
  if (online) {
    await loadEntries();
  } else {
    renderEntriesMessage("Cannot reach the service.");
  }
}

init().catch((error) => {
  setConnection("offline", "Offline");
  showError("issueError", error.message);
});
