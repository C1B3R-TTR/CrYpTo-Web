const $ = (id) => document.getElementById(id);

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

function setupDropzone(inputId, onChange) {
  const zone = document.querySelector(`.dropzone[data-for="${inputId}"]`);
  const input = $(inputId);
  const nameEl = zone.querySelector("[data-name]");

  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    nameEl.textContent = input.files[0] ? input.files[0].name : "";
    onChange(input.files[0]);
  });

  ["dragover", "dragenter"].forEach((ev) =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.classList.remove("dragover");
    })
  );
  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) {
      input.files = e.dataTransfer.files;
      nameEl.textContent = file.name;
      onChange(file);
    }
  });
}

function setStatus(id, text, cls) {
  const el = $(id);
  el.textContent = text;
  el.className = "status " + (cls || "");
}

async function postForm(url, form, statusId, busyText) {
  const btn = $(statusId.replace("-status", "-btn"));
  btn.disabled = true;
  setStatus(statusId, busyText, "wait");
  try {
    const resp = await fetch(url, { method: "POST", body: form });
    if (!resp.ok) {
      let msg = "Error del servidor.";
      try {
        const data = await resp.json();
        msg = data.error || msg;
      } catch (_) {}
      setStatus(statusId, "✗ " + msg, "err");
      return null;
    }
    const blob = await resp.blob();
    const header = resp.headers.get("X-Filename");
    const filename = header ? decodeURIComponent(header) : null;
    return { blob, filename };
  } catch (_) {
    setStatus(statusId, "✗ No se pudo contactar el servidor local.", "err");
    return null;
  } finally {
    btn.disabled = false;
  }
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "archivo";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

setupDropzone("encrypt-file", (file) => {
  $("encrypt-btn").disabled = !file;
  setStatus("encrypt-status", file ? formatSize(file.size) + " listo para cifrar" : "", "");
});

$("encrypt-btn").addEventListener("click", async () => {
  const file = $("encrypt-file").files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  const result = await postForm("/api/encrypt", form, "encrypt-status", "Cifrando…");
  if (result) {
    triggerDownload(result.blob, result.filename);
    setStatus("encrypt-status", "✓ Descargado: " + result.filename, "ok");
  }
});

setupDropzone("decrypt-file", async (file) => {
  $("decrypt-btn").disabled = !file;
  setStatus("decrypt-status", "Analizando archivo…", "wait");
  $("decrypt-note").textContent = "Carga el archivo y pulsa Descifrar.";
  if (!file) return;

  const form = new FormData();
  form.append("file", file);
  try {
    const resp = await fetch("/api/inspect", { method: "POST", body: form });
    if (!resp.ok) {
      const data = await resp.json();
      setStatus("decrypt-status", "✗ " + (data.error || "Archivo inválido."), "err");
      return;
    }
    const info = await resp.json();
    if (info.needs_master_key) {
      $("decrypt-note").textContent =
        "Archivo v" + info.version + " del desktop: descífralo con la app de escritorio CryptoVault.";
      setStatus("decrypt-status", formatSize(file.size) + " · v" + info.version + " (desktop)", "");
    } else {
      $("decrypt-note").textContent =
        "Archivo autocontenido: no necesitas nada más, pulsa Descifrar.";
      setStatus("decrypt-status", formatSize(file.size) + " · v5 autocontenido", "");
    }
  } catch (_) {
    setStatus("decrypt-status", "✗ No se pudo analizar el archivo.", "err");
  }
});

$("decrypt-btn").addEventListener("click", async () => {
  const file = $("decrypt-file").files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  const result = await postForm("/api/decrypt", form, "decrypt-status", "Descifrando…");
  if (result) {
    triggerDownload(result.blob, result.filename);
    setStatus("decrypt-status", "✓ Descargado: " + result.filename, "ok");
  }
});
