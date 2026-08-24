"use strict";

const state = { account: null, region: null, space: null, selectedEndpoints: [], endpoints: [], credSeq: 0, editingPentestId: null, editingSpaceId: null, selectedResources: [], availableResources: [], spaceEndpoints: [] };

const $ = (s) => document.querySelector(s);
const el = (t, c, x) => { const n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = x; return n; };

async function api(path, { method = "GET", body } = {}) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  let data = null; try { data = await res.json(); } catch {}
  if (!res.ok) throw new Error((data && data.detail) || `Erro ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg, kind = "") {
  const t = $("#toast"); t.textContent = msg; t.className = `toast-host show ${kind}`;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = "toast-host"), 3200);
}

const fmtDateTime = (iso) => { if (!iso) return "—"; const d = iso.slice(0, 10).split("-"); return `${d[2]}/${d[1]}/${d[0]} ${iso.slice(11, 16)}`; };

function statusBadge(status) {
  const map = { FAILED: "badge-failed", VERIFIED: "badge-verified", COMPLETED: "badge-verified", VERIFYING: "badge-verifying", PENDING: "badge-pending", RUNNING: "badge-running" };
  return el("span", `badge-status ${map[status] || ""}`, status);
}

// ---- Spaces ----
async function loadSpaces() {
  state.account = $("#in-account").value.trim();
  state.region = $("#in-region").value;
  if (!state.account) return toast("Informe a conta AWS.", "err");
  const btn = $("#btn-load-spaces"); btn.disabled = true; btn.textContent = "Carregando…";
  try {
    const spaces = await api("/api/context/spaces", { method: "POST", body: { account_id: state.account, region: state.region } });
    renderSpaces(spaces);
    $("#sum-account").textContent = state.account; $("#sum-region").textContent = state.region;
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; btn.textContent = "Carregar Spaces"; }
}

function renderSpaces(spaces) {
  const tb = $("#tbody-spaces"); tb.innerHTML = "";
  if (!spaces.length) { tb.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-3">Nenhum Space nesta conta/região.</td></tr>`; return; }
  for (const s of spaces) {
    const tr = el("tr", "selectable");
    const rc = el("td"); const r = el("input"); r.type = "radio"; r.name = "space"; r.className = "form-check-input"; rc.appendChild(r);
    tr.appendChild(rc);
    tr.appendChild(el("td", "mono", s.space_id));
    tr.appendChild(el("td", null, s.name));
    tr.appendChild(el("td", "text-muted", s.description || ""));
    const ac = el("td");
    const editBtn = el("button", "btn btn-sm btn-outline-primary", "Editar");
    editBtn.addEventListener("click", (ev) => { ev.stopPropagation(); editSpace(s); });
    ac.appendChild(editBtn); tr.appendChild(ac);
    tr.addEventListener("click", () => { r.checked = true; selectSpace(s, tr); });
    tb.appendChild(tr);
  }
}

async function selectSpace(space, tr) {
  state.space = space;
  cancelEditPentest(); // troca de Space encerra qualquer edição/criação em andamento
  document.querySelectorAll("#tbody-spaces tr").forEach((row) => row.classList.remove("is-selected"));
  if (tr) tr.classList.add("is-selected");
  $("#sum-space").textContent = `${space.name} (${space.space_id})`;
  $("#next-step").textContent = "Atualize os Pentests ou preencha o formulário para criar um novo.";
  $("#btn-refresh-pentests").disabled = false; $("#btn-create").disabled = false;
  $("#in-resource-filter").hidden = true; $("#resource-picker").hidden = true;
  state.availableResources = [];
  renderConnectedResources();
  await refreshPentests(); // cancelEditPentest() já disparou listEndpoints() para o novo Space
}

// ---- Pentests ----
async function refreshPentests() {
  if (!state.space) return;
  const tb = $("#tbody-pentests");
  try {
    const items = await api(`/api/pentests/space/${state.space.space_id}`);
    tb.innerHTML = "";
    if (!items.length) { tb.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">Nenhum pentest neste Space.</td></tr>`; return; }
    for (const p of items) {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", `${p.id.slice(0, 18)}…`));
      tr.appendChild(el("td", null, p.title));
      const st = el("td"); st.appendChild(statusBadge(p.status)); tr.appendChild(st);
      const a = el("td"); a.appendChild(el("span", "mono truncate", (p.target?.endpoints || []).join(", ") || "—")); tr.appendChild(a);
      tr.appendChild(el("td", null, fmtDateTime(p.created_at)));
      const ac = el("td");
      if (p.status === "PENDING") {
        const startBtn = el("button", "btn btn-sm btn-outline-success me-1", "Iniciar");
        startBtn.addEventListener("click", () => startPentest(p, startBtn));
        ac.appendChild(startBtn);
      }
      const editBtn = el("button", "btn btn-sm btn-outline-primary", "Editar");
      editBtn.addEventListener("click", () => startEditPentest(p));
      ac.appendChild(editBtn); tr.appendChild(ac);
      tb.appendChild(tr);
    }
  } catch (e) { toast(e.message, "err"); }
}

async function startPentest(pentest, btn) {
  btn.disabled = true; btn.textContent = "Iniciando…";
  try {
    const r = await api(`/api/pentests/${pentest.id}/start`, { method: "POST", body: { space_id: state.space.space_id } });
    toast(`Pentest ${pentest.id.slice(0, 15)}… ${r.status}.`, r.status === "FAILED" ? "err" : "ok");
    await refreshPentests();
  } catch (e) { toast(e.message, "err"); btn.disabled = false; btn.textContent = "Iniciar"; }
}

// ---- Editar Pentest ----
function startEditPentest(pentest) {
  state.editingPentestId = pentest.id;
  $("#in-title").value = pentest.title || "";
  $("#in-vpc").value = pentest.network?.vpc_id || "";
  $("#in-subnet").value = pentest.network?.subnet_id || "";
  $("#in-sg").value = pentest.network?.security_group_id || "";
  state.selectedEndpoints = [...(pentest.target?.endpoints || [])];
  state.selectedResources = [...(pentest.resources || [])];
  $("#in-role").value = pentest.target?.service_role_arn || "";
  $("#pentest-form-title").textContent = `✏️ Editando Pentest ${pentest.id}`;
  $("#pentest-form-title").classList.add("sa-editing-title");
  $("#pentest-form-section").classList.add("sa-card--editing");
  $("#btn-create").textContent = "Salvar alterações";
  $("#btn-cancel-edit").hidden = false;
  renderSelectedEndpoints();
  renderEndpointList();
  renderConnectedResources();
  $("#btn-create").closest("section").scrollIntoView({ behavior: "smooth", block: "start" });
  toast("Edite os campos e clique em Salvar alterações.");
}

function cancelEditPentest() {
  state.editingPentestId = null; state.selectedEndpoints = []; state.selectedResources = [];
  ["#in-title", "#in-vpc", "#in-subnet", "#in-sg", "#in-role"].forEach((s) => ($(s).value = ""));
  $("#pentest-form-title").textContent = "🛡️ Criar novo Pentest";
  $("#pentest-form-title").classList.remove("sa-editing-title");
  $("#pentest-form-section").classList.remove("sa-card--editing");
  $("#btn-create").textContent = "Criar Pentest";
  $("#btn-cancel-edit").hidden = true;
  renderConnectedResources();
  listEndpoints();
}

// ---- Endpoints (múltiplos alvos) ----
async function listEndpoints() {
  if (!state.space) return;
  try {
    const eps = await api(`/api/targets/endpoints?space_id=${encodeURIComponent(state.space.space_id)}`);
    state.endpoints = eps;
    renderEndpointList();
    refreshAccessUrlOptions();
  } catch (e) { toast(e.message, "err"); }
}

function renderEndpointList() {
  const box = $("#endpoint-list"); box.innerHTML = "";
  if (!state.endpoints.length) { box.innerHTML = `<div class="text-muted small p-2">Nenhum endpoint verificado neste Space.</div>`; return; }
  state.endpoints.forEach((ep) => box.appendChild(renderEndpoint(ep)));
}

function renderEndpoint(ep) {
  const isSelected = state.selectedEndpoints.includes(ep.url);
  const row = el("div", "sa-ep-row" + (isSelected ? " is-selected" : ""));
  const info = el("div", "sa-ep-info");
  info.appendChild(el("div", "sa-ep-url", ep.url));
  const badgeCls = ep.status === "SEM STATUS" ? "badge-status" : `badge-status badge-${ep.status.toLowerCase()}`;
  info.appendChild(el("span", badgeCls, ep.status));
  row.appendChild(info);
  const actions = el("div", "sa-ep-actions");
  const sel = el("button", `btn btn-sm ${isSelected ? "btn-primary" : "btn-outline-primary"}`, isSelected ? "✓ Selecionado" : "Selecionar");
  sel.addEventListener("click", () => toggleEndpointSelection(ep.url));
  const ver = el("button", "btn btn-sm btn-outline-secondary", "Verify");
  ver.addEventListener("click", () => verifyEndpoint(ep.url, ver, ep.id));
  actions.append(sel, ver); row.appendChild(actions);
  return row;
}

function toggleEndpointSelection(url) {
  const idx = state.selectedEndpoints.indexOf(url);
  if (idx >= 0) state.selectedEndpoints.splice(idx, 1);
  else state.selectedEndpoints.push(url);
  renderSelectedEndpoints();
  renderEndpointList();
  refreshAccessUrlOptions();
}

function renderSelectedEndpoints() {
  const box = $("#selected-endpoints"); box.innerHTML = "";
  $("#selected-count").textContent = state.selectedEndpoints.length;
  state.selectedEndpoints.forEach((url) => {
    const chip = el("span", "sa-chip");
    chip.appendChild(el("span", null, url));
    const rm = el("button", "btn-close", null);
    rm.type = "button"; rm.setAttribute("aria-label", "Remover");
    rm.addEventListener("click", () => toggleEndpointSelection(url));
    chip.appendChild(rm);
    box.appendChild(chip);
  });
}

async function verifyEndpoint(url, btn, targetDomainId) {
  btn.disabled = true; btn.textContent = "…";
  try {
    const r = await api("/api/targets/endpoints/verify", { method: "POST", body: { space_id: state.space.space_id, url, target_domain_id: targetDomainId || null } });
    $("#endpoint-detail").textContent = `${url} — ${r.status}${r.detail ? " · " + r.detail : ""}`;
    toast(`Verify: ${r.status}`, r.status === "VERIFIED" ? "ok" : "err");
    await listEndpoints();
  } catch (e) { toast(e.message, "err"); btn.disabled = false; btn.textContent = "Verify"; }
}

function refreshAccessUrlOptions() {
  const urls = state.selectedEndpoints.length ? state.selectedEndpoints : state.endpoints.map((ep) => ep.url);
  document.querySelectorAll(".c-accessurl").forEach((sel) => {
    const cur = sel.value;
    sel.innerHTML = `<option value="">Select target URL</option>`;
    urls.forEach((url) => { const o = el("option", null, url); o.value = url; sel.appendChild(o); });
    sel.value = cur;
  });
}

// ---- Listas AWS com caixa de resultados ----
// opts permite reutilizar a mesma lógica em qualquer formulário (Pentest ou
// Criar Agent Space): targetInput/resultsBox/vpcInput/errorBox sobrescrevem
// os seletores padrão do formulário de Pentest.
async function fillList(kind, opts = {}) {
  const region = state.region || $("#in-region").value;
  const vpcInput = opts.vpcInput || "#in-vpc";
  const errorBox = opts.errorBox || "#vpc-error";
  if ($(errorBox)) $(errorBox).hidden = true;
  try {
    let items = [], box, input, fmt;
    if (kind === "vpcs") {
      items = await api(`/api/network/vpcs?region=${region}`);
      box = opts.resultsBox || "#vpc-results"; input = opts.targetInput || "#in-vpc";
      fmt = (v) => [v.vpc_id, v.name || v.cidr_block || ""];
    } else if (kind === "subnets") {
      const vpc = $(vpcInput).value.trim(); if (!vpc) return toast("Informe a VPC antes de listar subnets.", "err");
      items = await api(`/api/network/vpcs/${vpc}/subnets?region=${region}`);
      box = opts.resultsBox || "#subnet-results"; input = opts.targetInput || "#in-subnet";
      fmt = (s) => [s.subnet_id, s.availability_zone || ""];
    } else if (kind === "sgs") {
      const vpc = $(vpcInput).value.trim();
      items = await api(`/api/network/security-groups?region=${region}${vpc ? "&vpc_id=" + vpc : ""}`);
      box = opts.resultsBox || "#sg-results"; input = opts.targetInput || "#in-sg";
      fmt = (g) => [g.group_id, g.name || ""];
    } else if (kind === "roles") {
      items = await api(`/api/targets/roles?region=${region}`);
      box = opts.resultsBox || "#role-results"; input = opts.targetInput || "#in-role";
      fmt = (r) => [r.arn, r.role_name || ""];
    }
    renderResults(box, input, items.map(fmt));
    toast(`${items.length} resultado(s).`);
  } catch (e) {
    if (kind === "vpcs" && $(errorBox)) $(errorBox).hidden = false;
    toast(e.message, "err");
  }
}

function renderResults(boxSel, inputSel, pairs) {
  const box = $(boxSel); box.innerHTML = "";
  if (!pairs.length) { box.appendChild(el("div", "sa-res-empty", "Nenhum resultado.")); return; }
  for (const [value, label] of pairs) {
    const row = el("div", "sa-res-row");
    row.appendChild(el("span", "mono", value));
    if (label) row.appendChild(el("span", "text-muted small", label));
    row.addEventListener("click", () => { $(inputSel).value = value; box.querySelectorAll(".sa-res-row").forEach((r) => r.classList.remove("is-selected")); row.classList.add("is-selected"); });
    box.appendChild(row);
  }
}

// ---- Recursos ----
function renderConnectedResources() {
  const tb = $("#tbody-resources"); tb.innerHTML = "";
  $("#res-count").textContent = state.selectedResources.length;
  if (!state.selectedResources.length) {
    tb.innerHTML = `<tr><td colspan="3" class="text-center text-muted py-3">No resources selected for this pentest.</td></tr>`;
    return;
  }
  state.selectedResources.forEach((r) => {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", r.name));
    tr.appendChild(el("td", "text-muted", r.type || "s3"));
    const ac = el("td", "text-end");
    const rm = el("button", "btn btn-sm btn-outline-danger", "Remove");
    rm.type = "button"; rm.addEventListener("click", () => toggleResourceSelection(r));
    ac.appendChild(rm); tr.appendChild(ac);
    tb.appendChild(tr);
  });
}

function isResourceSelected(r) {
  return state.selectedResources.some((s) => s.s3_uri === r.s3_uri);
}

function toggleResourceSelection(r) {
  const idx = state.selectedResources.findIndex((s) => s.s3_uri === r.s3_uri);
  if (idx >= 0) state.selectedResources.splice(idx, 1);
  else state.selectedResources.push({ name: r.name, type: "s3", s3_uri: r.s3_uri });
  renderConnectedResources();
  renderResourcePicker();
}

function renderResourcePicker() {
  const box = $("#resource-picker"); box.innerHTML = "";
  const filter = $("#in-resource-filter").value.trim().toLowerCase();
  const items = state.availableResources.filter((r) => !filter || r.name.toLowerCase().includes(filter));
  if (!items.length) { box.appendChild(el("div", "sa-res-empty", "Nenhum resource encontrado neste Space.")); return; }
  items.forEach((r) => {
    const row = el("div", "sa-res-row");
    const info = el("span", "mono truncate", r.name);
    row.appendChild(info);
    const selected = isResourceSelected(r);
    const btn = el("button", `btn btn-sm ${selected ? "btn-primary" : "btn-outline-primary"}`, selected ? "✓ Selecionado" : "Selecionar");
    btn.type = "button"; btn.addEventListener("click", () => toggleResourceSelection(r));
    row.appendChild(btn);
    box.appendChild(row);
  });
}

async function listResources() {
  if (!state.space) return toast("Selecione um Space.", "err");
  try {
    state.availableResources = await api(`/api/resources?space_id=${encodeURIComponent(state.space.space_id)}`);
    $("#in-resource-filter").hidden = false;
    $("#resource-picker").hidden = false;
    renderResourcePicker();
  } catch (e) { toast(e.message, "err"); }
}

async function uploadFile() {
  if (!state.space) return toast("Selecione um Space.", "err");
  const f = $("#in-file").files[0]; if (!f) return toast("Escolha um arquivo primeiro.", "err");
  try {
    const pre = await api("/api/resources/upload-url", { method: "POST", body: { space_id: state.space.space_id, filename: f.name, content_type: f.type || "application/octet-stream" } });
    const headers = pre.content_type ? { "Content-Type": pre.content_type } : {};
    const up = await fetch(pre.url, { method: "PUT", headers, body: f });
    if (!up.ok) throw new Error(`Falha no upload S3 (${up.status})`);
    state.selectedResources.push({ name: f.name, type: "s3", s3_uri: pre.s3_uri });
    renderConnectedResources();
    $("#in-file").value = "";
    toast(`Enviado: ${f.name}`, "ok");
  } catch (e) { toast(e.message, "err"); }
}

// ---- Credenciais dinâmicas ----
function addCredential(name) {
  state.credSeq += 1;
  const tpl = $("#cred-tpl").content.firstElementChild.cloneNode(true);
  const title = name || `Credential${state.credSeq}`;
  tpl.querySelector(".cred-title").textContent = title;
  tpl.querySelector(".c-actor").value = title;

  // radios precisam de name único por card
  const radios = tpl.querySelectorAll(".c-mode");
  radios.forEach((r) => (r.name = `cred-mode-${state.credSeq}`));

  // alternância input/advanced
  const panelIn = tpl.querySelector(".c-panel-input");
  const panelAdv = tpl.querySelector(".c-panel-adv");
  radios.forEach((r) => r.addEventListener("change", () => {
    const adv = tpl.querySelector(".c-mode[value='advanced']").checked;
    panelIn.hidden = adv; panelAdv.hidden = !adv;
  }));

  tpl.querySelector(".c-edit").addEventListener("click", () => {
    const novo = prompt("Novo nome da credencial:", tpl.querySelector(".cred-title").textContent);
    if (novo) { tpl.querySelector(".cred-title").textContent = novo; tpl.querySelector(".c-actor").value = novo; }
  });
  tpl.querySelector(".c-remove").addEventListener("click", () => {
    if (document.querySelectorAll("[data-cred]").length <= 1) return toast("Mantenha ao menos uma credencial.", "err");
    tpl.remove();
  });
  tpl.querySelector(".c-clear").addEventListener("click", () => {
    tpl.querySelectorAll(".c-user,.c-pass,.c-totp,.c-prompt,.c-secretarn").forEach((i) => (i.value = ""));
  });

  tpl.querySelector(".c-qr").addEventListener("click", () => tpl.querySelector(".c-qr-file").click());
  tpl.querySelector(".c-qr-file").addEventListener("change", (e) => handleQrUpload(e, tpl));

  $("#cred-list").appendChild(tpl);
  refreshAccessUrlOptions();
}

function extractTotpSecret(text) {
  if (!text) return null;
  if (text.startsWith("otpauth://")) {
    try { return new URL(text).searchParams.get("secret"); } catch { return null; }
  }
  return text.trim();
}

function handleQrUpload(event, card) {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (typeof jsQR !== "function") return toast("Leitor de QR code não carregado.", "err");
  const reader = new FileReader();
  reader.onload = () => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const result = jsQR(imageData.data, imageData.width, imageData.height);
      if (!result) return toast("Nenhum QR code encontrado na imagem.", "err");
      const secret = extractTotpSecret(result.data);
      if (!secret) return toast("QR code lido, mas sem segredo TOTP reconhecível.", "err");
      card.querySelector(".c-totp").value = secret;
      toast("Segredo TOTP importado do QR code.", "ok");
    };
    img.onerror = () => toast("Não foi possível carregar a imagem.", "err");
    img.src = reader.result;
  };
  reader.onerror = () => toast("Falha ao ler o arquivo.", "err");
  reader.readAsDataURL(file);
}

function collectCredentials() {
  const out = [];
  document.querySelectorAll("[data-cred]").forEach((card) => {
    const actor = card.querySelector(".c-actor").value.trim() || card.querySelector(".cred-title").textContent;
    const adv = card.querySelector(".c-mode[value='advanced']").checked;
    if (adv) {
      const arn = card.querySelector(".c-secretarn").value.trim();
      if (!arn) return;
      out.push({ actor_identifier: actor, mode: "advanced", secret_arn: arn, access_url: card.querySelector(".c-accessurl").value || null, login_prompt: card.querySelector(".c-prompt").value.trim() || null });
    } else {
      const user = card.querySelector(".c-user").value.trim();
      const pass = card.querySelector(".c-pass").value;
      const totp = card.querySelector(".c-totp").value.trim();
      if (!user && !pass && !totp) return;
      out.push({ actor_identifier: actor, mode: "input", username: user || null, password: pass || null, totp_secret: totp || null, access_url: card.querySelector(".c-accessurl").value || null, login_prompt: card.querySelector(".c-prompt").value.trim() || null });
    }
  });
  return out;
}

// ---- Criar / Salvar ----
async function createPentest() {
  if (!state.space) return toast("Selecione um Space.", "err");
  const title = $("#in-title").value.trim();
  if (!title) return toast("Informe o título do pentest.", "err");
  const network = { vpc_id: $("#in-vpc").value.trim() || null, subnet_id: $("#in-subnet").value.trim() || null, security_group_id: $("#in-sg").value.trim() || null };
  const target = { endpoints: [...new Set(state.selectedEndpoints)], service_role_arn: $("#in-role").value.trim() || null };
  const editing = state.editingPentestId;
  const btn = $("#btn-create"); btn.disabled = true; btn.textContent = editing ? "Salvando…" : "Criando…";
  try {
    if (editing) {
      const p = await api(`/api/pentests/${editing}`, { method: "PATCH", body: { space_id: state.space.space_id, title, network, target, resources: state.selectedResources } });
      toast(`Pentest ${p.id.slice(0, 15)}… atualizado.`, "ok");
      cancelEditPentest();
    } else {
      const payload = { space_id: state.space.space_id, title, network, target, credentials: collectCredentials(), resources: state.selectedResources };
      const p = await api("/api/pentests", { method: "POST", body: payload });
      toast(`Pentest ${p.id.slice(0, 15)}… criado (${p.status}).`, "ok");
      $("#in-title").value = "";
    }
    await refreshPentests();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; btn.textContent = state.editingPentestId ? "Salvar alterações" : "Criar Pentest"; }
}

// ---- Criar / Editar Space ----
function renderSpaceEndpoints() {
  const box = $("#sp-endpoints"); box.innerHTML = "";
  $("#sp-endpoints-count").textContent = state.spaceEndpoints.length;
  state.spaceEndpoints.forEach((ep) => {
    const chip = el("span", "sa-chip");
    chip.appendChild(el("span", null, ep.url));
    const rm = el("button", "btn-close", null);
    rm.type = "button"; rm.setAttribute("aria-label", "Remover");
    rm.addEventListener("click", () => {
      state.spaceEndpoints = state.spaceEndpoints.filter((e) => e !== ep);
      renderSpaceEndpoints();
    });
    chip.appendChild(rm);
    box.appendChild(chip);
  });
}

async function createSpaceEndpoint() {
  const url = $("#sp-endpoint").value.trim();
  if (!url) return toast("Informe a URL do alvo.", "err");
  const verification_method = $("#sp-endpoint-verification").value;
  const region = state.region || $("#in-region").value;
  const btn = $("#btn-sp-create-endpoint"); btn.disabled = true; btn.textContent = "Criando…";
  try {
    const ep = await api("/api/targets/endpoints", { method: "POST", body: { region, url, verification_method } });
    toast(`Alvo ${ep.url} criado (${ep.status}).`, "ok");
    state.spaceEndpoints.push(ep);
    $("#sp-endpoint").value = "";
    renderSpaceEndpoints();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; btn.textContent = "+ Criar alvo"; }
}

function setSpaceModalMode(editing) {
  $("#modal-space-title").textContent = editing ? "Editar Agent Space" : "Criar Agent Space";
  $("#btn-save-space").textContent = editing ? "Salvar alterações" : "Criar Space";
  $("#sp-endpoint-hint").textContent = editing
    ? "Cria um novo target domain e o associa a este Space ao salvar."
    : "Cria um novo target domain e o associa a este Space assim que ele for criado.";
  $("#sp-footer-hint").textContent = editing
    ? "Rede e role em branco não apagam o que já está no Space — deixe preenchido o que quiser manter."
    : "Nome é obrigatório; os demais associam recursos AWS ao Space (awsResources).";
}

function resetSpaceModal() {
  state.editingSpaceId = null;
  ["#sp-name", "#sp-desc", "#sp-role", "#sp-vpc", "#sp-subnet", "#sp-sg", "#sp-endpoint"].forEach((s) => ($(s).value = ""));
  ["#sp-vpc-results", "#sp-subnet-results", "#sp-sg-results", "#sp-role-results"].forEach((s) => { if ($(s)) $(s).innerHTML = ""; });
  state.spaceEndpoints = []; renderSpaceEndpoints();
  setSpaceModalMode(false);
}

function fillSpaceResources(res) {
  const vpc = ((res && res.vpcs) || [])[0] || {};
  $("#sp-vpc").value = vpc.vpcArn || "";
  $("#sp-subnet").value = (vpc.subnetArns || [])[0] || "";
  $("#sp-sg").value = (vpc.securityGroupArns || [])[0] || "";
  $("#sp-role").value = ((res && res.iamRoles) || [])[0] || "";
}

async function spaceEndpointsOf(space) {
  // Só busca a lista quando o Space tem alvos associados: sem target_domain_ids
  // o backend cai no "todos os target domains da região", que não é deste Space.
  if (space.endpoints && space.endpoints.length) return space.endpoints.map((e) => ({ id: e.id || null, url: e.url }));
  if (space.target_domain_ids && space.target_domain_ids.length) {
    try { return await api(`/api/targets/endpoints?space_id=${encodeURIComponent(space.space_id)}`); }
    catch { return []; }
  }
  return [];
}

async function editSpace(space) {
  resetSpaceModal();
  state.editingSpaceId = space.space_id;
  setSpaceModalMode(true);
  if (window.bootstrap) bootstrap.Modal.getOrCreateInstance($("#modal-space")).show();
  try {
    const full = await api(`/api/context/spaces/${encodeURIComponent(space.space_id)}`);
    $("#sp-name").value = full.name || "";
    $("#sp-desc").value = full.description || "";
    fillSpaceResources(full.aws_resources);
    state.spaceEndpoints = await spaceEndpointsOf(full);
    renderSpaceEndpoints();
  } catch (e) { toast(e.message, "err"); }
}

function spaceResourcesFromModal() {
  const role = $("#sp-role").value.trim(), vpc = $("#sp-vpc").value.trim(),
        subnet = $("#sp-subnet").value.trim(), sg = $("#sp-sg").value.trim();
  const res = {};
  if (role) res.iamRoles = [role];
  if (vpc || subnet || sg) {
    res.vpcs = [{ vpcArn: vpc || undefined, subnetArns: subnet ? [subnet] : undefined, securityGroupArns: sg ? [sg] : undefined }];
  }
  return res;
}

async function saveSpace() {
  const name = $("#sp-name").value.trim();
  if (!name) return toast("Informe o nome do Space.", "err");
  const editing = state.editingSpaceId;
  const body = { name, description: $("#sp-desc").value.trim() || null };
  const res = spaceResourcesFromModal();
  if (Object.keys(res).length) body.aws_resources = res;
  const targetDomainIds = state.spaceEndpoints.filter((ep) => ep.id).map((ep) => ep.id);
  const endpointUrls = state.spaceEndpoints.filter((ep) => !ep.id).map((ep) => ep.url);
  const btn = $("#btn-save-space"); btn.disabled = true; btn.textContent = editing ? "Salvando…" : "Criando…";
  try {
    let sp;
    if (editing) {
      // PATCH: a lista de alvos do modal substitui a associação atual.
      body.target_domain_ids = targetDomainIds;
      body.endpoints = endpointUrls;
      sp = await api(`/api/context/spaces/${encodeURIComponent(editing)}`, { method: "PATCH", body });
      toast(`Space ${sp.space_id} atualizado.`, "ok");
      if (state.space && state.space.space_id === sp.space_id) {
        state.space = sp;
        $("#sum-space").textContent = `${sp.name} (${sp.space_id})`;
      }
    } else {
      if (targetDomainIds.length) body.target_domain_ids = targetDomainIds;
      if (endpointUrls.length) body.endpoints = endpointUrls;
      sp = await api("/api/context/spaces/create", { method: "POST", body });
      toast(`Space ${sp.space_id} criado.`, "ok");
    }
    resetSpaceModal();
    if (window.bootstrap) bootstrap.Modal.getInstance($("#modal-space"))?.hide();
    if (state.account) await loadSpaces();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; btn.textContent = state.editingSpaceId ? "Salvar alterações" : "Criar Space"; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#btn-load-spaces").addEventListener("click", loadSpaces);
  $("#btn-save-space").addEventListener("click", saveSpace);
  $("#btn-new-space").addEventListener("click", resetSpaceModal);
  $("#btn-sp-create-endpoint").addEventListener("click", createSpaceEndpoint);
  $("#btn-refresh-pentests").addEventListener("click", refreshPentests);
  $("#btn-list-endpoints").addEventListener("click", listEndpoints);
  $("#btn-list-resources").addEventListener("click", listResources);
  $("#btn-upload").addEventListener("click", uploadFile);
  $("#in-resource-filter").addEventListener("input", renderResourcePicker);
  $("#btn-create").addEventListener("click", createPentest);
  $("#btn-cancel-edit").addEventListener("click", cancelEditPentest);
  $("#btn-add-cred").addEventListener("click", () => addCredential());
  document.querySelectorAll("[data-list]").forEach((b) => b.addEventListener("click", () => fillList(b.dataset.list, {
    targetInput: b.dataset.target, resultsBox: b.dataset.results, vpcInput: b.dataset.vpcInput, errorBox: b.dataset.error,
  })));
  addCredential("Credential1");  // começa com uma credencial, como na tela
  renderConnectedResources();
});
