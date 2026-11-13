"use strict";
const messages = {
  en: {
    language: "Language",
    eyebrow: "IDENTITY & ACCESS",
    title: "Your directory. Connected.",
    intro: "Manage the trusted connection between Active Directory and your home.",
    ingress: "Home Assistant Ingress",
    directory: "Directory",
    transport: "Transport",
    trust: "Certificate trust",
    secureConnection: "SECURE CONNECTION",
    certTitle: "Trusted CA certificates",
    certIntro:
      "Upload your AD certificate authority to verify the identity of your domain controller over LDAPS.",
    chooseFile: "Choose a CA certificate",
    dropHint: "or drop a file here · PEM, CER, CRT or DER · up to 128 KiB",
    certHelp:
      "Use a public root or intermediate CA certificate. Private keys and domain controller leaf certificates are rejected. Changes apply to the next connection.",
    upload: "Upload certificate",
    remove: "Remove uploaded certificate",
    directoryAccess: "DIRECTORY ACCESS",
    connectionTitle: "Connection details",
    server: "Server",
    userGroup: "Allowed group",
    adminGroup: "Administrator group",
    optionsHelp:
      "Edit server and group settings in the app's Configuration tab, then restart the app.",
    check: "Test directory connection",
    getStarted: "HOME ASSISTANT SIGN-IN",
    setupTitle: "Connect your login",
    step1: "Download and install the authentication script",
    step1Help:
      "Download the script, then copy it from your computer into the same Home Assistant folder as configuration.yaml using File editor or Studio Code Server. Name it auth-wrapper.py, without a .txt suffix. Core reads it as /config/auth-wrapper.py. Downloading alone does not install it. It contains a private API key; keep it out of shared folders and Git.",
    download: "Download auth-wrapper.py",
    step2: "Add the authentication provider",
    step2Help:
      "Merge this into configuration.yaml. Keep the local Home Assistant provider as a fallback.",
    step3: "Restart Home Assistant",
    step3Help:
      "Keep your current administrator session open and test AD sign-in in a private browser window. Members of the allowed group get access.",
    roleNote:
      "New users receive the standard user role unless they belong to the configured administrator group. Home Assistant applies these roles only when it creates the account.",
    footer: "Active Directory Authentication",
    removeTitle: "Remove the uploaded CA?",
    removeHelp:
      "New connections will use the configured PEM, an existing certificate file, or the system trust store. LDAPS may fail if none of these trusts your domain controller.",
    cancel: "Cancel",
    confirmRemove: "Remove certificate",
    configured: "Configured",
    notConfigured: "Setup needed",
    verified: "Certificate verification enabled",
    unverified: "Certificate verification disabled",
    plain: "Unencrypted LDAP",
    system: "System trust store",
    uploaded: "Uploaded CA",
    configuration: "Configured PEM",
    file: "Existing CA file",
    invalid: "Invalid certificate",
    noAdmin: "Standard users only",
    loading: "Working…",
    loadError:
      "Could not load app status. Open the app through Home Assistant and refresh the page.",
    sizeError: "Choose one certificate file smaller than 128 KiB.",
    saved: "Certificate saved. New connections will use this CA bundle.",
    removed: "Uploaded certificate removed.",
    success:
      "Directory bind succeeded. Server, credentials and TLS settings are working. User and group access is checked at sign-in.",
    expires: "Expires",
    requestError: "The request failed. Refresh the page and try again.",
    tlsWarning:
      "LDAP is not using verified TLS. Enable LDAPS and certificate verification in Configuration.",
    setupWarning:
      "Complete the required fields in the app's Configuration tab, then restart the app.",
    empty: "No custom CA. The system trust store is used for verified LDAPS.",
    diagnosticsEyebrow: "TROUBLESHOOTING",
    diagnosticsTitle: "Authentication diagnostics",
    refreshDiagnostics: "Refresh log",
    diagnosticsHelp:
      "Read recent application messages without a live log stream. The request count shows whether the login script has reached this app since startup.",
    noAuthRequests:
      "No authentication requests received since startup. Check the Active Directory provider in Core, the configured script and its connection to the app.",
    authRequests: "Authentication requests received",
    lastAuthResponse: "Last completed response",
    noAuthResponse: "No completed response yet",
    noDiagnosticLogs: "No application log entries are available yet.",
  },
  nb: {
    language: "Språk",
    eyebrow: "IDENTITET OG TILGANG",
    title: "Din katalog. Tilkoblet.",
    intro: "Administrer den sikre forbindelsen mellom Active Directory og hjemmet ditt.",
    ingress: "Home Assistant Ingress",
    directory: "Katalog",
    transport: "Forbindelse",
    trust: "Sertifikattillit",
    secureConnection: "SIKKER FORBINDELSE",
    certTitle: "Klarerte CA-sertifikater",
    certIntro:
      "Last opp AD-sertifikatutstederen for å bekrefte identiteten til domenekontrolleren over LDAPS.",
    chooseFile: "Velg et CA-sertifikat",
    dropHint: "eller slipp en fil her · PEM, CER, CRT eller DER · inntil 128 KiB",
    certHelp:
      "Bruk et offentlig rot- eller mellomliggende CA-sertifikat. Private nøkler og domenekontrollerens eget sertifikat avvises. Endringen gjelder neste forbindelse.",
    upload: "Last opp sertifikat",
    remove: "Fjern opplastet sertifikat",
    directoryAccess: "KATALOGTILGANG",
    connectionTitle: "Tilkoblingsdetaljer",
    server: "Server",
    userGroup: "Tillatt gruppe",
    adminGroup: "Administratorgruppe",
    optionsHelp:
      "Endre server og grupper i appens Konfigurasjon-fane. Start deretter appen på nytt.",
    check: "Test katalogforbindelse",
    getStarted: "INNLOGGING I HOME ASSISTANT",
    setupTitle: "Koble til innloggingen",
    step1: "Last ned og installer autentiseringsskriptet",
    step1Help:
      "Last ned skriptet, og kopier det fra PC-en til samme mappe som configuration.yaml i Home Assistant med File editor eller Studio Code Server. Filen skal hete auth-wrapper.py, uten .txt til slutt. Core leser den som /config/auth-wrapper.py. Nedlasting alene installerer ikke filen. Den inneholder en privat API-nøkkel og må holdes utenfor delte mapper og Git.",
    download: "Last ned auth-wrapper.py",
    step2: "Legg til autentiseringstilbyderen",
    step2Help:
      "Flett dette inn i configuration.yaml. Behold den lokale Home Assistant-tilbyderen som reserve.",
    step3: "Start Home Assistant på nytt",
    step3Help:
      "Behold administratorøkten åpen og test AD-innlogging i et privat nettleservindu. Medlemmer av den tillatte gruppen får tilgang.",
    roleNote:
      "Nye brukere får vanlig brukerrolle med mindre de er medlem av den angitte administratorgruppen. Home Assistant bruker disse rollene bare når kontoen opprettes.",
    footer: "Active Directory-autentisering",
    removeTitle: "Fjerne opplastet CA?",
    removeHelp:
      "Nye forbindelser vil bruke konfigurert PEM, en eksisterende sertifikatfil eller systemets sertifikatlager. LDAPS kan feile dersom ingen av disse klarerer domenekontrolleren.",
    cancel: "Avbryt",
    confirmRemove: "Fjern sertifikat",
    configured: "Konfigurert",
    notConfigured: "Oppsett kreves",
    verified: "Sertifikatvalidering er aktivert",
    unverified: "Sertifikatvalidering er deaktivert",
    plain: "Ukryptert LDAP",
    system: "Systemets sertifikatlager",
    uploaded: "Opplastet CA",
    configuration: "Konfigurert PEM",
    file: "Eksisterende CA-fil",
    invalid: "Ugyldig sertifikat",
    noAdmin: "Kun vanlige brukere",
    loading: "Arbeider…",
    loadError:
      "Kunne ikke hente appstatus. Åpne appen gjennom Home Assistant og last siden på nytt.",
    sizeError: "Velg én sertifikatfil mindre enn 128 KiB.",
    saved: "Sertifikatet er lagret. Nye forbindelser vil bruke denne CA-pakken.",
    removed: "Det opplastede sertifikatet er fjernet.",
    success:
      "Katalogtilkoblingen lykkes. Server, påloggingsinformasjon og TLS-innstillinger fungerer. Bruker- og gruppetilgang kontrolleres ved innlogging.",
    expires: "Utløper",
    requestError: "Forespørselen mislyktes. Last siden på nytt og prøv igjen.",
    tlsWarning:
      "LDAP bruker ikke validert TLS. Aktiver LDAPS og sertifikatvalidering under Konfigurasjon.",
    setupWarning: "Fyll ut obligatoriske felt i appens Konfigurasjon-fane, og start appen på nytt.",
    empty: "Ingen egendefinert CA. Systemets sertifikatlager brukes til validert LDAPS.",
    diagnosticsEyebrow: "FEILSØKING",
    diagnosticsTitle: "Diagnostikk for innlogging",
    refreshDiagnostics: "Oppdater logg",
    diagnosticsHelp:
      "Les de siste appmeldingene uten en løpende loggstrøm. Antall forespørsler viser om innloggingsskriptet har nådd appen siden oppstart.",
    noAuthRequests:
      "Ingen innloggingsforespørsler mottatt siden oppstart. Kontroller Active Directory-tilbyderen i Core, skriptet og forbindelsen til appen.",
    authRequests: "Innloggingsforespørsler mottatt",
    lastAuthResponse: "Siste fullførte svar",
    noAuthResponse: "Ingen fullførte svar ennå",
    noDiagnosticLogs: "Ingen appmeldinger er tilgjengelige ennå.",
  },
};
let language = /^(nb|nn|no)/i.test(navigator.language) ? "nb" : "en";
try {
  language = localStorage.getItem("ldapauth-language") || language;
} catch {}
if (!messages[language]) language = "en";
let state = null;
let selectedFile = null;
let pending = false;
let noticeKey = null;
let connectionKey = null;
let diagnosticState = null;
const $ = (id) => document.getElementById(id);
const t = (key) => messages[language][key] || key;
const set = (id, value) => {
  $(id).textContent = value;
};
function notify(message, error = false) {
  noticeKey = null;
  set("notice", message);
  $("notice").className = error ? "error" : "";
  $("notice").hidden = false;
}
function notifyKey(key, error = false) {
  notify(t(key), error);
  noticeKey = key;
}
function connectionMessage(key) {
  connectionKey = key;
  set("check-result", t(key));
}
function translate() {
  document.documentElement.lang = language;
  $("language").value = language;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  $("language").setAttribute("aria-label", t("language"));
  if (state) render();
  if (noticeKey) set("notice", t(noticeKey));
  if (connectionKey) set("check-result", t(connectionKey));
  renderDiagnostics();
}
function renderDiagnostics() {
  if (!diagnosticState) return;
  const last =
    diagnosticState.last_status === null
      ? t("noAuthResponse")
      : `${t("lastAuthResponse")}: HTTP ${diagnosticState.last_status}`;
  set(
    "diagnostics-summary",
    diagnosticState.auth_requests === 0
      ? t("noAuthRequests")
      : `${t("authRequests")}: ${diagnosticState.auth_requests}. ${last}`,
  );
  set(
    "diagnostics-log",
    diagnosticState.logs.length ? diagnosticState.logs.join("\n") : t("noDiagnosticLogs"),
  );
}
async function refreshDiagnostics() {
  $("refresh-diagnostics").disabled = true;
  try {
    diagnosticState = await api("api/diagnostics");
    renderDiagnostics();
  } catch (error) {
    set("diagnostics-summary", error.message);
  } finally {
    $("refresh-diagnostics").disabled = false;
  }
}
$("refresh-diagnostics").addEventListener("click", refreshDiagnostics);
function render() {
  set("directory-state", t(state.configured ? "configured" : "notConfigured"));
  set("directory-host", state.server.host);
  set("transport-state", state.server.tls ? "LDAPS / TLS" : "LDAP");
  set(
    "transport-detail",
    t(!state.server.tls ? "plain" : state.server.verify ? "verified" : "unverified"),
  );
  set("trust-state", t(state.certificate.source));
  set(
    "trust-detail",
    state.certificate.certificates.length
      ? `${state.certificate.certificates.length} CA`
      : t(state.certificate.source),
  );
  set("server", `${state.server.host}:${state.server.port}`);
  set("users", state.groups.users || "—");
  set("admins", state.groups.admins || t("noAdmin"));
  set("version", `v${state.version}`);
  $("remove").hidden = !state.certificate.uploaded;
  $("check").disabled = !state.configured || pending;
  const list = $("certificate-list");
  list.replaceChildren();
  state.certificate.certificates.forEach((certificate) => {
    const item = document.createElement("div");
    item.className = "certificate-item";
    const subject = document.createElement("strong");
    subject.textContent = certificate.subject;
    const details = document.createElement("span");
    details.textContent = `${t("expires")} ${new Date(certificate.expires).toLocaleDateString(language)} · ${certificate.issuer}`;
    const fingerprint = document.createElement("span");
    fingerprint.className = "fingerprint";
    fingerprint.textContent = `SHA-256 ${certificate.sha256}`;
    item.append(subject, details, fingerprint);
    list.append(item);
  });
  if (!state.certificate.certificates.length) {
    const empty = document.createElement("p");
    empty.className = "help";
    empty.textContent = state.certificate.valid ? t("empty") : state.certificate.error;
    list.append(empty);
  }
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "X-CSRF-Token": state?.csrf_token || "", ...options.headers },
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail.length < 500 && !detail.includes("<") ? detail : t("requestError"));
  }
  return response.json();
}
function busy(value) {
  pending = value;
  $("upload").disabled = value || !selectedFile || !state;
  $("check").disabled = value || !state?.configured;
  $("remove").disabled = value;
  $("certificate-file").disabled = value;
  $("confirm-remove").disabled = value;
}
function choose(file) {
  if (pending) return;
  selectedFile = file && file.size > 0 && file.size < 128 * 1024 ? file : null;
  set(
    "selected-file",
    selectedFile ? `${selectedFile.name} · ${(selectedFile.size / 1024).toFixed(1)} KiB` : "",
  );
  if (file && !selectedFile) notifyKey("sizeError", true);
  busy(false);
}
$("language").addEventListener("change", (event) => {
  language = event.target.value;
  try {
    localStorage.setItem("ldapauth-language", language);
  } catch {}
  translate();
});
$("certificate-file").addEventListener("change", (event) => choose(event.target.files[0]));
$("drop-zone").addEventListener("dragover", (event) => {
  event.preventDefault();
  $("drop-zone").classList.add("dragging");
});
$("drop-zone").addEventListener("dragleave", () => $("drop-zone").classList.remove("dragging"));
$("drop-zone").addEventListener("drop", (event) => {
  event.preventDefault();
  $("drop-zone").classList.remove("dragging");
  if (event.dataTransfer.files.length === 1) choose(event.dataTransfer.files[0]);
  else notifyKey("sizeError", true);
});
$("upload").addEventListener("click", async () => {
  if (!selectedFile || pending) return;
  busy(true);
  try {
    await api("api/certificate", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: selectedFile,
    });
    state = await api("api/status");
    selectedFile = null;
    $("certificate-file").value = "";
    set("selected-file", "");
    render();
    notifyKey("saved");
  } catch (error) {
    notify(error.message, true);
  } finally {
    busy(false);
  }
});
$("check").addEventListener("click", async () => {
  busy(true);
  connectionMessage("loading");
  try {
    await api("api/check", { method: "POST" });
    connectionMessage("success");
  } catch (error) {
    connectionKey = null;
    set("check-result", error.message);
  } finally {
    busy(false);
  }
});
$("remove").addEventListener("click", () => $("remove-dialog").showModal());
$("cancel-remove").addEventListener("click", () => $("remove-dialog").close());
$("confirm-remove").addEventListener("click", async () => {
  if (pending) return;
  busy(true);
  try {
    await api("api/certificate", { method: "DELETE" });
    state = await api("api/status");
    render();
    $("remove-dialog").close();
    notifyKey("removed");
  } catch (error) {
    $("remove-dialog").close();
    notify(error.message, true);
  } finally {
    busy(false);
  }
});
function syncHomeAssistantTheme() {
  try {
    const parentApp = window.parent.document.querySelector("home-assistant");
    const dark = parentApp?.hass?.themes?.darkMode;
    if (typeof dark === "boolean") {
      document.documentElement.dataset.theme = dark ? "dark" : "light";
    }
  } catch {}
}
syncHomeAssistantTheme();
try {
  if (window.parent !== window) {
    new MutationObserver(syncHomeAssistantTheme).observe(window.parent.document.documentElement, {
      attributes: true,
      subtree: true,
      attributeFilter: ["style", "class"],
    });
  }
} catch {}
translate();
api("api/status")
  .then((result) => {
    state = result;
    render();
    busy(false);
    if (!state.configured) notifyKey("setupWarning");
    else if (!state.server.tls || !state.server.verify) notifyKey("tlsWarning", true);
    else if (!state.certificate.valid) notify(state.certificate.error, true);
    refreshDiagnostics();
  })
  .catch(() => notifyKey("loadError", true));
