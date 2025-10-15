-- Store rrweb session chunks per form/session
CREATE TABLE IF NOT EXISTS form_sessions (
  form_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  data TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (form_id, session_id, idx)
);

CREATE INDEX IF NOT EXISTS idx_form_sessions_lookup
  ON form_sessions (form_id, session_id);
