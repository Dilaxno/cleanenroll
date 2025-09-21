from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
import json
import uuid
from pydantic import BaseModel, EmailStr

# Email + Firebase Admin
try:
    # When running as a package (e.g., backend.*)
    from ..utils.email import render_email, send_email_html  # type: ignore
except Exception:
    # When running flat from repo root
    from utils.email import render_email, send_email_html  # type: ignore
try:
    import firebase_admin
    from firebase_admin import auth as admin_auth, credentials as admin_credentials
    _FB_AVAILABLE = True
except Exception:
    firebase_admin = None  # type: ignore
    admin_auth = None  # type: ignore
    admin_credentials = None  # type: ignore
    _FB_AVAILABLE = False

router = APIRouter()

# Persistence dir (filesystem-based)
DATA_DIR = os.path.join(os.getcwd(), "data", "forms")
os.makedirs(DATA_DIR, exist_ok=True)


class FieldSchema(BaseModel):
    id: str
    label: str
    type: str  # text, number, checkbox, dropdown, date, location
    required: bool = False
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None  # for dropdown/select


class ThemeSchema(BaseModel):
    primaryColor: str = "#4f46e5"
    backgroundColor: str = "#ffffff"
    textColor: str = "#111827"
    inputBgColor: str = "#ffffff"
    inputTextColor: str = "#111827"
    inputBorderColor: str = "#d1d5db"
    inputBorderRadius: int = 8


class FormConfig(BaseModel):
    title: str = "Untitled Form"
    subtitle: str = ""
    theme: ThemeSchema = ThemeSchema()
    fields: List[FieldSchema] = []


# -----------------------------
# Auth & Email
# -----------------------------

class PasswordResetRequest(BaseModel):
    email: EmailStr


def _ensure_firebase_initialized():
    if not _FB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Firebase Admin SDK not available on server.")
    if not firebase_admin._apps:  # type: ignore
        # Initialize with GOOGLE_APPLICATION_CREDENTIALS or application default
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        try:
            if cred_path and os.path.exists(cred_path):
                cred = admin_credentials.Certificate(cred_path)
            else:
                cred = admin_credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to initialize Firebase Admin: {e}")


@router.post("/api/auth/password-reset")
async def send_password_reset_email(req: PasswordResetRequest):
    """Generate a Firebase password reset link and email it with our branded template.
    Always return 200 to avoid revealing whether an account exists.
    """
    try:
        _ensure_firebase_initialized()
    except HTTPException as init_err:
        # If Firebase Admin is unavailable, don't error-leak; respond 200 but skip send
        return {"status": "ok"}

    continue_url = os.getenv("RESET_CONTINUE_URL", "https://cleanenroll.com/reset-password")

    link = None
    try:
        link = admin_auth.generate_password_reset_link(
            req.email,
            action_code_settings={
                "url": continue_url,
                "handle_code_in_app": True,
            },
        )
    except Exception as e:
        # Common case: user not found -> do not leak via 4xx; just pretend success
        # You may inspect the error message, but we keep it generic here.
        link = None

    if link:
        subject = "Reset your CleanEnroll password"
        html = render_email("base.html", {
            "subject": subject,
            "preheader": "Create a new password to get back into your account.",
            "title": "Reset your password",
            "intro": "We received a request to reset your password. Click the button below to choose a new one.",
            "content_html": "",
            "cta_label": "Reset Password",
            "cta_url": link,
        })

        try:
            send_email_html(req.email, subject, html)
        except Exception:
            # Do not leak mailer issues to client
            pass

    # Always return ok to avoid user enumeration
    return {"status": "ok"}


# -----------------------------
# Utility helpers
# -----------------------------

def _form_path(form_id: str) -> str:
    return os.path.join(DATA_DIR, f"{form_id}.json")


def _save_form(data: Dict) -> str:
    form_id = uuid.uuid4().hex
    data_with_id = {**data, "id": form_id}
    with open(_form_path(form_id), "w", encoding="utf-8") as f:
        json.dump(data_with_id, f, ensure_ascii=False, indent=2)
    return form_id


def _load_form(form_id: str) -> Dict:
    path = _form_path(form_id)
    if not os.path.exists(path):
        raise FileNotFoundError
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------------
# API (moved from main.py)
# -----------------------------

@router.post("/api/forms")
async def create_form(cfg: FormConfig):
    # Basic type guard for field.type
    allowed_types = {"text", "number", "checkbox", "dropdown", "date", "location"}
    for fld in cfg.fields:
        if fld.type not in allowed_types:
            raise HTTPException(status_code=400, detail=f"Unsupported field type: {fld.type}")
        if fld.type == "dropdown" and (not fld.options or len([o for o in fld.options if o.strip()]) == 0):
            raise HTTPException(status_code=400, detail="Dropdown fields require at least one option")

    # Persist
    data = cfg.dict()
    form_id = _save_form(data)

    # Build iframe snippet
    embed_url = f"/embed/{form_id}"
    iframe_snippet = f'<iframe src="{embed_url}" width="100%" height="600" frameborder="0"></iframe>'

    return {
        "id": form_id,
        "embedUrl": embed_url,
        "iframeSnippet": iframe_snippet,
    }


@router.get("/api/forms/{form_id}")
async def get_form(form_id: str):
    try:
        data = _load_form(form_id)
        return data
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Form not found")


# -----------------------------
# HTML pages (Builder and Embed)
# -----------------------------

BUILDER_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>CleanEnroll - Form Builder</title>
  <style>
    :root {
      --bg: #f3f4f6;
      --panel: #ffffff;
      --text: #111827;
      --muted: #6b7280;
      --border: #e5e7eb;
      --primary: #4f46e5;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica Neue, Arial, \"Apple Color Emoji\", \"Segoe UI Emoji\";
      background: var(--bg); color: var(--text);
    }
    .container { display: grid; grid-template-columns: 380px 1fr; gap: 16px; padding: 16px; min-height: 100vh; }
    .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
    .panel h2 { margin: 0 0 12px; font-size: 18px; }
    .section { margin-bottom: 16px; }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input[type=text], input[type=number], input[type=color], select, textarea {
      width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; outline: none;
      background: #fff; color: var(--text);
    }
    textarea { resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .fields-list { display: flex; flex-direction: column; gap: 12px; }
    .field-item { border: 1px dashed var(--border); border-radius: 10px; padding: 10px; }
    .field-head { display: flex; gap: 8px; align-items: center; }
    .field-head .grow { flex: 1; }
    .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border); background: #fff; cursor: pointer; }
    .btn.primary { background: var(--primary); color: white; border-color: var(--primary); }
    .btn.danger { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .toolbar { display: flex; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 10px; }

    /* Preview styles */
    .preview-wrap { padding: 8px; }
    .preview { max-width: 720px; margin: 0 auto; background: var(--form-bg, #ffffff); color: var(--form-text, #111827); border-radius: 16px; border: 1px solid var(--border); box-shadow: 0 10px 20px rgba(0,0,0,0.05); }
    .preview .header { padding: 24px; border-bottom: 1px solid var(--border); }
    .preview .header h1 { margin: 0 0 6px; font-size: 24px; }
    .preview .header p { margin: 0; color: var(--muted); }
    .preview .body { padding: 20px 24px; }
    .form-field { margin-bottom: 16px; }
    .form-field label { margin-bottom: 6px; }
    .form-field input[type=text],
    .form-field input[type=number],
    .form-field input[type=date],
    .form-field select,
    .form-field textarea {
      width: 100%; padding: 12px; background: var(--input-bg, #fff); color: var(--input-text, #111827);
      border: 1px solid var(--input-border, #d1d5db); border-radius: var(--radius, 8px);
      outline: none; transition: box-shadow .15s ease, border-color .15s ease;
    }
    .form-field input[type=text]:focus,
    .form-field input[type=number]:focus,
    .form-field input[type=date]:focus,
    .form-field select:focus,
    .form-field textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px color-mix(in oklab, var(--primary) 20%, transparent);
    }
    .muted { color: var(--muted); font-size: 12px; }
    .save-box { margin-top: 12px; padding: 12px; border: 1px dashed var(--border); border-radius: 10px; background: #fafafa; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"panel\">
      <div class=\"toolbar\">
        <h2>Form Settings</h2>
        <button id=\"saveBtn\" class=\"btn primary\">Save & Generate Embed</button>
      </div>

      <div class=\"section\">
        <label>Title</label>
        <input id=\"titleInput\" type=\"text\" placeholder=\"Enter form title\" />
      </div>
      <div class=\"section\">
        <label>Subtitle</label>
        <textarea id=\"subtitleInput\" rows=\"2\" placeholder=\"Enter subtitle/description\"></textarea>
      </div>

      <div class=\"section\">
        <h2>Theme</h2>
        <div class=\"row\">
          <div>
            <label>Primary color</label>
            <input id=\"primaryColor\" type=\"color\" value=\"#4f46e5\" />
          </div>
          <div>
            <label>Background color</label>
            <input id=\"backgroundColor\" type=\"color\" value=\"#ffffff\" />
          </div>
        </div>
        <div class=\"row\">
          <div>
            <label>Text color</label>
            <input id=\"textColor\" type=\"color\" value=\"#111827\" />
          </div>
          <div>
            <label>Input background</label>
            <input id=\"inputBgColor\" type=\"color\" value=\"#ffffff\" />
          </div>
        </div>
        <div class=\"row\">
          <div>
            <label>Input text color</label>
            <input id=\"inputTextColor\" type=\"color\" value=\"#111827\" />
          </div>
          <div>
            <label>Input border color</label>
            <input id=\"inputBorderColor\" type=\"color\" value=\"#d1d5db\" />
          </div>
        </div>
        <div class=\"section\">
          <label>Input border radius (px)</label>
          <input id=\"inputBorderRadius\" type=\"number\" min=\"0\" max=\"30\" value=\"8\" />
        </div>
      </div>

      <div class=\"section\">
        <div class=\"toolbar\">
          <h2>Fields</h2>
          <button id=\"addFieldBtn\" class=\"btn\">+ Add Field</button>
        </div>
        <div id=\"fieldsList\" class=\"fields-list\"></div>
      </div>

      <div id=\"saveBox\" class=\"save-box\" style=\"display:none\;\">
        <div><strong>Embed code</strong> (copy & paste into your site):</div>
        <pre id=\"iframeCode\" style=\"white-space: pre-wrap; background:#0b1020; color:#d1e7ff; padding:10px; border-radius:8px;\"></pre>
        <button id=\"copyIframeBtn\" class=\"btn\">Copy code</button>
        <div class=\"muted\">If the iframe src starts with /embed/, prepend your server origin (e.g. https://your-domain.com/embed/XYZ).</div>
      </div>
    </div>

    <div class=\"panel preview-wrap\">
      <h2>Live Preview</h2>
      <div id=\"preview\"></div>
    </div>
  </div>

<script>
(function(){
  const state = {
    title: 'Untitled Form',
    subtitle: '',
    theme: {
      primaryColor: '#4f46e5',
      backgroundColor: '#ffffff',
      textColor: '#111827',
      inputBgColor: '#ffffff',
      inputTextColor: '#111827',
      inputBorderColor: '#d1d5db',
      inputBorderRadius: 8,
    },
    fields: []
  };

  // Helpers
  function uid(){ return Math.random().toString(36).slice(2,10); }

  function renderPreview(){
    const container = document.getElementById('preview');
    const t = state.theme;
    const styleVars = `--form-bg:${t.backgroundColor};--form-text:${t.textColor};--input-bg:${t.inputBgColor};--input-text:${t.inputTextColor};--input-border:${t.inputBorderColor};--radius:${t.inputBorderRadius}px;--primary:${t.primaryColor}`;

    const header = `
      <div class=\"header\"> 
        <h1>${escapeHtml(state.title || '')}</h1>
        ${state.subtitle ? `<p>${escapeHtml(state.subtitle)}</p>` : ''}
      </div>`;

    const fieldsHtml = state.fields.map(f => renderField(f)).join('');
    container.innerHTML = `
      <div class=\"preview\" style=\"${styleVars}\">${header}<div class=\"body\">${fieldsHtml}</div></div>
    `;
  }

  function escapeHtml(str){
    return String(str).replace(/[&<>\"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]));
  }

  function renderField(f){
    const req = f.required ? ' <span class=\"muted\">(required)</span>' : '';
    const label = `<label>${escapeHtml(f.label || 'Untitled')}${req}</label>`;
    const ph = f.placeholder ? ` placeholder=\"${escapeHtml(f.placeholder)}\"` : '';
    if (f.type === 'text') {
      return `<div class=\"form-field\">${label}<input type=\"text\"${ph} /></div>`;
    }
    if (f.type === 'number') {
      return `<div class=\"form-field\">${label}<input type=\"number\"${ph} /></div>`;
    }
    if (f.type === 'checkbox') {
      return `<div class=\"form-field\"><label><input type=\"checkbox\" /> ${escapeHtml(f.label || 'Checkbox')}</label></div>`;
    }
    if (f.type === 'dropdown') {
      const opts = (f.options||[]).map(o => `<option>${escapeHtml(o)}</option>`).join('');
      return `<div class=\"form-field\">${label}<select>${opts}</select></div>`;
    }
    if (f.type === 'date') {
      return `<div class=\"form-field\">${label}<input type=\"date\" /></div>`;
    }
    if (f.type === 'location') {
      return `<div class=\"form-field\">${label}
        <div style=\"display:flex; gap:8px;\">
          <input type=\"text\" readonly placeholder=\"Latitude,Longitude\" />
          <button class=\"btn\" type=\"button\">Use my location</button>
        </div>
        <div class=\"muted\">HTML5 Geolocation will be used in the embedded form.</div>
      </div>`;
    }
    return `<div class=\"form-field\">${label}<input type=\"text\"${ph} /></div>`;
  }

  function fieldEditor(f){
    const wrap = document.createElement('div');
    wrap.className = 'field-item';
    wrap.innerHTML = `
      <div class=\"field-head\">
        <input class=\"grow label\" type=\"text\" placeholder=\"Field label\" value=\"${escapeAttr(f.label || '')}\" />
        <select class=\"type\">
          <option value=\"text\" ${f.type==='text'?'selected':''}>Text</option>
          <option value=\"number\" ${f.type==='number'?'selected':''}>Number</option>
          <option value=\"checkbox\" ${f.type==='checkbox'?'selected':''}>Checkbox</option>
          <option value=\"dropdown\" ${f.type==='dropdown'?'selected':''}>Dropdown</option>
          <option value=\"date\" ${f.type==='date'?'selected':''}>Calendar (Date)</option>
          <option value=\"location\" ${f.type==='location'?'selected':''}>Location</option>
        </select>
        <label style=\"display:flex;align-items:center;gap:6px\"><input class=\"required\" type=\"checkbox\" ${f.required?'checked':''}/> required</label>
        <button class=\"btn danger remove\" type=\"button\">Remove</button>
      </div>
      <div class=\"row\" style=\"margin-top:8px\">
        <div><label>Placeholder</label><input class=\"placeholder\" type=\"text\" value=\"${escapeAttr(f.placeholder||'')}\" /></div>
        <div class=\"optsBox\" style=\"display:${f.type==='dropdown'?'block':'none'}\">
          <label>Dropdown options (comma separated)</label>
          <input class=\"options\" type=\"text\" value=\"${escapeAttr((f.options||[]).join(', '))}\" />
        </div>
      </div>
    `;

    const onChange = () => {
      f.label = sel('.label').value;
      f.type = sel('.type').value;
      f.required = sel('.required').checked;
      f.placeholder = sel('.placeholder').value;
      const optsBox = sel('.optsBox');
      if (f.type === 'dropdown') {
        optsBox.style.display = 'block';
        const raw = sel('.options').value || '';
        f.options = raw.split(',').map(s => s.trim()).filter(Boolean);
      } else {
        optsBox.style.display = 'none';
        f.options = [];
      }
      renderPreview();
    };

    function sel(q){ return wrap.querySelector(q); }

    wrap.addEventListener('input', onChange);
    sel('.remove').addEventListener('click', () => {
      state.fields = state.fields.filter(x => x.id !== f.id);
      wrap.remove();
      renderPreview();
    });

    return wrap;
  }

  function renderEditors(){
    const list = document.getElementById('fieldsList');
    list.innerHTML = '';
    state.fields.forEach(f => list.appendChild(fieldEditor(f)));
  }

  function addField(){
    const f = { id: uid(), label: 'Untitled', type: 'text', required: false, placeholder: '' };
    state.fields.push(f);
    renderEditors();
    renderPreview();
  }

  // Inputs
  const bind = (id, keyPath, transform=v=>v) => {
    const el = document.getElementById(id);
    const set = (val) => {
      const keys = keyPath.split('.');
      let obj = state; for (let i=0;i<keys.length-1;i++){ obj = obj[keys[i]]; }
      obj[keys[keys.length-1]] = transform(val);
      renderPreview();
    };
    el.addEventListener('input', e => set(e.target.value));
    if (el.type === 'number') el.addEventListener('change', e => set(e.target.value));
  };

  bind('titleInput','title');
  bind('subtitleInput','subtitle');
  bind('primaryColor','theme.primaryColor');
  bind('backgroundColor','theme.backgroundColor');
  bind('textColor','theme.textColor');
  bind('inputBgColor','theme.inputBgColor');
  bind('inputTextColor','theme.inputTextColor');
  bind('inputBorderColor','theme.inputBorderColor');
  bind('inputBorderRadius','theme.inputBorderRadius', v => parseInt(v||'0',10));

  document.getElementById('addFieldBtn').addEventListener('click', addField);

  // Save
  document.getElementById('saveBtn').addEventListener('click', async () => {
    try {
      const res = await fetch('/api/forms', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(state)
      });
      if (!res.ok) throw new Error('Failed to save form');
      const data = await res.json();
      // If server returned relative embedUrl, build absolute snippet
      const origin = window.location.origin;
      const src = data.embedUrl.startsWith('http') ? data.embedUrl : origin + data.embedUrl;
      const snippet = `<iframe src=\"${src}\" width=\"100%\" height=\"600\" frameborder=\"0\"></iframe>`;
      document.getElementById('iframeCode').textContent = snippet;
      document.getElementById('saveBox').style.display = 'block';
    } catch (e) {
      alert(e.message || String(e));
    }
  });

  document.getElementById('copyIframeBtn').addEventListener('click', async () => {
    const txt = document.getElementById('iframeCode').textContent;
    try { await navigator.clipboard.writeText(txt); } catch(e) {}
  });

  function escapeAttr(s){ return String(s).replace(/"/g,'&quot;'); }

  // Initial seed
  state.fields = [
    { id: uid(), label: 'Full name', type: 'text', required: true, placeholder: 'Jane Doe' },
    { id: uid(), label: 'Email', type: 'text', required: true, placeholder: 'jane@example.com' },
    { id: uid(), label: 'When can we contact you?', type: 'date', required: false },
    { id: uid(), label: 'How did you hear about us?', type: 'dropdown', options: ['Search', 'Friend', 'Ad'], required: false }
  ];
  document.getElementById('titleInput').value = state.title;
  document.getElementById('subtitleInput').value = state.subtitle;
  renderEditors();
  renderPreview();
})();
</script>
</body>
</html>
"""


@router.get("/", response_class=HTMLResponse)
async def builder_page():
    return HTMLResponse(content=BUILDER_HTML)


@router.get("/embed/{form_id}", response_class=HTMLResponse)
async def embed_page(form_id: str):
    # Simple embed page that fetches the config and renders it
    html = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>CleanEnroll - Embedded Form</title>
  <style>
    :root { --border: #e5e7eb; --muted: #6b7280; }
    * { box-sizing: border-box; }
    body { margin: 0; background: transparent; }
    .form { max-width: 720px; margin: 0 auto; }
    .card { background: var(--form-bg, #ffffff); color: var(--form-text, #111827); border-radius: 16px; border: 1px solid var(--border); }
    .header { padding: 20px 24px; border-bottom: 1px solid var(--border); }
    .header h1 { margin: 0 0 6px; font-size: 22px; }
    .header p { margin: 0; color: var(--muted); }
    .body { padding: 20px 24px; }
    .field { margin-bottom: 14px; }
    .field label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 12px; }
    input[type=text], input[type=number], input[type=date], select, textarea {
      width: 100%; padding: 12px; background: var(--input-bg, #fff); color: var(--input-text, #111827);
      border: 1px solid var(--input-border, #d1d5db); border-radius: var(--radius, 8px);
      outline: none; transition: box-shadow .15s ease, border-color .15s ease;
    }
    input[type=text]:focus, input[type=number]:focus, input[type=date]:focus, select:focus, textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px color-mix(in oklab, var(--primary) 20%, transparent);
    }
    .actions { padding: 16px 24px 24px; }
    .btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 16px; border-radius: 10px; border: 1px solid transparent; background: var(--primary, #4f46e5); color: #fff; cursor: pointer; }
  </style>
</head>
<body>
  <div class=\"form\">
    <div id=\"card\" class=\"card\">
      <div class=\"header\">
        <h1 id=\"title\"></h1>
        <p id=\"subtitle\"></p>
      </div>
      <div id=\"body\" class=\"body\"></div>
      <div class=\"actions\"><button class=\"btn\" type=\"button\">Submit</button></div>
    </div>
  </div>
<script>
(function(){
  const FORM_ID = "__FORM_ID__";

  function escapeHtml(str){
    return String(str).replace(/[&<>\"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[s]));
  }

  function renderField(f){
    const req = f.required ? ' <span style=\"color:var(--muted)\;font-size:12px\">(required)</span>' : '';
    const labelHtml = `<label>${escapeHtml(f.label||'Untitled')}${req}</label>`;
    const ph = f.placeholder ? ` placeholder=\"${escapeHtml(f.placeholder)}\"` : '';
    if (f.type === 'text') { return `<div class=\"field\">${labelHtml}<input type=\"text\"${ph} /></div>`; }
    if (f.type === 'number') { return `<div class=\"field\">${labelHtml}<input type=\"number\"${ph} /></div>`; }
    if (f.type === 'checkbox') { return `<div class=\"field\"><label><input type=\"checkbox\" /> ${escapeHtml(f.label||'Checkbox')}</label></div>`; }
    if (f.type === 'dropdown') {
      const opts = (f.options||[]).map(o => `<option>${escapeHtml(o)}</option>`).join('');
      return `<div class=\"field\">${labelHtml}<select>${opts}</select></div>`; }
    if (f.type === 'date') { return `<div class=\"field\">${labelHtml}<input type=\"date\" /></div>`; }
    if (f.type === 'location') {
      const id = 'loc_' + Math.random().toString(36).slice(2,8);
      return `<div class=\"field\">${labelHtml}
        <div style=\"display:flex; gap:8px;\">
          <input id=\"${id}\" type=\"text\" readonly placeholder=\"Latitude,Longitude\" />
          <button class=\"btn\" type=\"button\" onclick=\"(function(){navigator.geolocation && navigator.geolocation.getCurrentPosition(function(p){document.getElementById('${id}').value=p.coords.latitude.toFixed(6)+','+p.coords.longitude.toFixed(6);});})()\">Use my location</button>
        </div>
      </div>`;
    }
    return `<div class=\"field\">${labelHtml}<input type=\"text\"${ph} /></div>`;
  }

  async function init(){
    try {
      const base = window.location.origin;
      const res = await fetch(base + '/api/forms/' + FORM_ID);
      if (!res.ok) throw new Error('Not found');
      const cfg = await res.json();

      // Theme
      const t = cfg.theme || {};
      const card = document.getElementById('card');
      card.style.setProperty('--form-bg', t.backgroundColor || '#ffffff');
      card.style.setProperty('--form-text', t.textColor || '#111827');
      card.style.setProperty('--input-bg', t.inputBgColor || '#ffffff');
      card.style.setProperty('--input-text', t.inputTextColor || '#111827');
      card.style.setProperty('--input-border', t.inputBorderColor || '#d1d5db');
      card.style.setProperty('--radius', (t.inputBorderRadius||8) + 'px');
      card.style.setProperty('--primary', t.primaryColor || '#4f46e5');

      document.getElementById('title').textContent = cfg.title || '';
      const sub = document.getElementById('subtitle');
      sub.textContent = cfg.subtitle || '';
      sub.style.display = cfg.subtitle ? 'block' : 'none';

      const body = document.getElementById('body');
      const fields = (cfg.fields||[]).map(renderField).join('');
      body.innerHTML = fields;
    } catch (e) {
      document.body.innerHTML = '<div style="padding:24px;font-family:sans-serif">Form not found</div>';
    }
  }

  init();
})();
</script>
</body>
</html>
"""
    html = html.replace("__FORM_ID__", form_id)
    return HTMLResponse(content=html)


# --------------
# Health endpoint
# --------------
@router.get("/health")
async def health():
    return {"status": "ok"}
