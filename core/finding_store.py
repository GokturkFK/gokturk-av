"""
GÖKTÜRK — Finding Store
SQLite tabanlı bulgu, oturum ve araç profili yönetimi.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).parent.parent / "data" / "findings.db"


class FindingStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS vehicle_profiles (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    profile_yaml TEXT NOT NULL,
                    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS test_sessions (
                    id                  TEXT PRIMARY KEY,
                    vehicle_profile_id  TEXT NOT NULL,
                    started_at          TEXT,
                    ended_at            TEXT,
                    status              TEXT DEFAULT 'created',
                    notes               TEXT,
                    FOREIGN KEY (vehicle_profile_id) REFERENCES vehicle_profiles(id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id                  TEXT PRIMARY KEY,
                    session_id          TEXT NOT NULL,
                    vehicle_profile_id  TEXT NOT NULL,
                    component_id        TEXT NOT NULL,
                    test_module_id      TEXT NOT NULL,
                    -- Taksonomi
                    r155_category       INTEGER,
                    r155_vector_id      TEXT DEFAULT '',
                    avcat_id            TEXT DEFAULT '',
                    -- ISO 21434 etki (none/low/medium/high/critical)
                    impact_safety       TEXT DEFAULT 'none',
                    impact_financial    TEXT DEFAULT 'none',
                    impact_operational  TEXT DEFAULT 'none',
                    impact_privacy      TEXT DEFAULT 'none',
                    -- Saldırı fizibilitesi (low/medium/high/very_high)
                    attack_feasibility  TEXT DEFAULT 'unknown',
                    -- Sonuç
                    status              TEXT NOT NULL,
                    title               TEXT NOT NULL,
                    description         TEXT DEFAULT '',
                    evidence_paths      TEXT DEFAULT '[]',
                    remediation         TEXT DEFAULT '',
                    cvss_score          REAL,
                    created_at          TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES test_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS test_module_registry (
                    id                  TEXT PRIMARY KEY,
                    name                TEXT NOT NULL,
                    surface             TEXT NOT NULL,
                    technique           TEXT NOT NULL,
                    r155_vector_id      TEXT DEFAULT '',
                    r155_category       INTEGER,
                    applicable_adapters TEXT DEFAULT '[]',
                    severity_hint       TEXT DEFAULT 'medium',
                    manifest_path       TEXT DEFAULT '',
                    enabled             INTEGER DEFAULT 1,
                    created_at          TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_findings_profile
                    ON findings(vehicle_profile_id);
                CREATE INDEX IF NOT EXISTS idx_findings_session
                    ON findings(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_vector
                    ON findings(r155_vector_id);
            """)

    # ── Vehicle Profiles ─────────────────────────────────────────────────────

    def save_profile(self, profile_id: str, name: str, profile_yaml: str) -> str:
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vehicle_profiles (id, name, profile_yaml, updated_at)
                VALUES (?, ?, ?, ?)
            """, (profile_id, name, profile_yaml, datetime.utcnow().isoformat()))
        return profile_id

    def get_profiles(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, name, created_at FROM vehicle_profiles ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_profile(self, profile_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vehicle_profiles WHERE id = ?", (profile_id,)
            ).fetchone()
        return dict(row) if row else None

    # ── Test Sessions ────────────────────────────────────────────────────────

    def create_session(self, vehicle_profile_id: str, notes: str = "") -> str:
        sid = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO test_sessions (id, vehicle_profile_id, started_at, status, notes)
                VALUES (?, ?, ?, 'running', ?)
            """, (sid, vehicle_profile_id, datetime.utcnow().isoformat(), notes))
        return sid

    def close_session(self, session_id: str, status: str = "completed"):
        with self._conn() as conn:
            conn.execute("""
                UPDATE test_sessions SET ended_at = ?, status = ? WHERE id = ?
            """, (datetime.utcnow().isoformat(), status, session_id))

    def get_sessions(self, vehicle_profile_id: Optional[str] = None) -> List[Dict]:
        with self._conn() as conn:
            if vehicle_profile_id:
                rows = conn.execute(
                    "SELECT * FROM test_sessions WHERE vehicle_profile_id=? ORDER BY started_at DESC",
                    (vehicle_profile_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM test_sessions ORDER BY started_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    # ── Findings ─────────────────────────────────────────────────────────────

    def add_finding(
        self,
        session_id: str,
        vehicle_profile_id: str,
        component_id: str,
        test_module_id: str,
        status: str,            # vulnerable / not_vulnerable / inconclusive / error
        title: str,
        r155_vector_id: str = "",
        r155_category: Optional[int] = None,
        avcat_id: str = "",
        impact_safety: str = "none",
        impact_financial: str = "none",
        impact_operational: str = "none",
        impact_privacy: str = "none",
        attack_feasibility: str = "unknown",
        description: str = "",
        evidence_paths: Optional[List[str]] = None,
        remediation: str = "",
        cvss_score: Optional[float] = None,
    ) -> str:
        fid = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO findings (
                    id, session_id, vehicle_profile_id, component_id, test_module_id,
                    r155_category, r155_vector_id, avcat_id,
                    impact_safety, impact_financial, impact_operational, impact_privacy,
                    attack_feasibility, status, title, description,
                    evidence_paths, remediation, cvss_score
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                fid, session_id, vehicle_profile_id, component_id, test_module_id,
                r155_category, r155_vector_id, avcat_id,
                impact_safety, impact_financial, impact_operational, impact_privacy,
                attack_feasibility, status, title, description,
                json.dumps(evidence_paths or []), remediation, cvss_score,
            ))
        return fid

    def get_findings(
        self,
        vehicle_profile_id: Optional[str] = None,
        session_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict]:
        conditions, params = [], []
        if vehicle_profile_id:
            conditions.append("vehicle_profile_id = ?"); params.append(vehicle_profile_id)
        if session_id:
            conditions.append("session_id = ?"); params.append(session_id)
        if status:
            conditions.append("status = ?"); params.append(status)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY created_at DESC", params
            ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["evidence_paths"] = json.loads(d.get("evidence_paths") or "[]")
            result.append(d)
        return result

    # ── Compliance / Coverage ─────────────────────────────────────────────────

    def get_compliance_coverage(self, vehicle_profile_id: Optional[str] = None) -> Dict:
        """UN R155 Annex 5 kapsam özeti."""
        cond = "WHERE vehicle_profile_id = ?" if vehicle_profile_id else ""
        params = [vehicle_profile_id] if vehicle_profile_id else []
        with self._conn() as conn:
            total   = conn.execute(f"SELECT COUNT(*) FROM findings {cond}", params).fetchone()[0]
            vuln    = conn.execute(
                f"SELECT COUNT(*) FROM findings {cond} {'AND' if cond else 'WHERE'} status='vulnerable'",
                params + []
            ).fetchone()[0] if not cond else conn.execute(
                "SELECT COUNT(*) FROM findings WHERE vehicle_profile_id=? AND status='vulnerable'",
                params
            ).fetchone()[0]
            vectors = conn.execute(
                f"SELECT r155_vector_id, status, COUNT(*) as cnt FROM findings "
                f"{cond} GROUP BY r155_vector_id, status ORDER BY r155_vector_id",
                params
            ).fetchall()
        return {
            "total": total,
            "vulnerable": vuln,
            "not_vulnerable": total - vuln,
            "vectors_tested": len(set(r["r155_vector_id"] for r in vectors)),
            "by_vector": [dict(r) for r in vectors],
        }

    # ── Module Registry ───────────────────────────────────────────────────────

    def register_module(self, mod: Dict[str, Any]):
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO test_module_registry
                (id, name, surface, technique, r155_vector_id, r155_category,
                 applicable_adapters, severity_hint, manifest_path)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                mod["id"], mod["name"], mod["surface"], mod["technique"],
                mod.get("r155_vector_id", ""), mod.get("r155_category"),
                json.dumps(mod.get("applicable_adapters", [])),
                mod.get("severity_hint", "medium"), mod.get("manifest_path", ""),
            ))

    def get_modules(self, surface: Optional[str] = None) -> List[Dict]:
        with self._conn() as conn:
            if surface:
                rows = conn.execute(
                    "SELECT * FROM test_module_registry WHERE enabled=1 AND surface=? ORDER BY name",
                    (surface,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM test_module_registry WHERE enabled=1 ORDER BY surface, name"
                ).fetchall()
        return [dict(r) for r in rows]
