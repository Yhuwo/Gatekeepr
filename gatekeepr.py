"""
Discord Verification Bot (Multi-Server Edition)
===============================================
Ephemeral image CAPTCHA + modal answer, with cooldowns, auto-kick after too
many failed attempts, mod-channel logging, and Patreon auto-verify.

This version supports MULTIPLE SERVERS from a single bot instance. Each
server's admins configure their own settings via /config slash commands,
stored in a SQLite database.

Requirements:
    pip install discord.py captcha

Bot setup (one-time, for YOU as the bot operator):
    1. Create an application at https://discord.com/developers/applications
    2. Bot tab -- enable SERVER MEMBERS INTENT
    3. Bot tab -- toggle PUBLIC BOT on if you want others to invite it
    4. Copy your bot token into the TOKEN value below (or use an env var)

End-user setup (for each server that invites the bot):
    1. Invite the bot using your public invite URL
    2. Create a role named "Verified" (or whatever) in their server
    3. Drag the BOT's role above Verified in Server Settings -> Roles
    4. Run /config set-verified-role, /config set-verify-channel, etc.
    5. Run /setup-verify in their #verify channel to post the button
    6. Run /grandfather to bulk-verify existing members
    7. Lock down @everyone channel permissions
"""

import discord
from discord import app_commands
from discord.ext import commands, tasks
from captcha.image import ImageCaptcha
import random
import io
import time
import sqlite3
import json
import os
import asyncio
from datetime import datetime
from pathlib import Path


# =============================================================================
# GLOBAL CONFIGURATION -- applies to the whole bot (all servers)
# =============================================================================

# Your bot's token. This reads from the DISCORD_BOT_TOKEN environment variable,
# which keeps the secret out of this file so the code itself stays safe to share.
#
# HOW TO SET IT:
#
# Quick test (temporary, resets when you close the terminal):
#   Linux / macOS:   export DISCORD_BOT_TOKEN="your_token_here"
#   Windows PowerShell:   $env:DISCORD_BOT_TOKEN="your_token_here"
#   Then in the same terminal: python verify_bot.py
#
# Permanent on a Linux VPS (recommended): set it in your systemd service file
# under the [Service] section:
#   Environment="DISCORD_BOT_TOKEN=your_token_here"
# See the VPS setup guide for the full systemd service example.
#
# If you'd rather just paste the token directly into this file, replace the
# line below with:   TOKEN = "your_token_here"
# and keep this file private.
TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")

# Path to the SQLite database file. Created automatically if it doesn't exist.
# Back this up regularly -- it contains all per-server settings.
DB_DIR = Path(__file__).parent / "guilds"
DB_DIR.mkdir(exist_ok=True)

# Where to write the public status JSON consumed by the website.
# The file is updated periodically with bot uptime, server count, and
# aggregate verification numbers. If the directory doesn't exist or isn't
# writable (e.g. running locally), the writer logs and skips silently.
STATUS_FILE = Path(os.environ.get("GATEKEEPR_STATUS_FILE", "/var/www/gatekeepr/status.json"))
STATUS_WRITE_INTERVAL_SECONDS = 60

# Bot startup time, set on import. Used for uptime calculation.
BOT_STARTED_AT = time.time()

# The CAPTCHA character set. Excludes confusing chars like 0/O/1/I/L.
# Applies globally; can't be customized per-server (keeps things simple).
CAPTCHA_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


# =============================================================================
# DATABASE LAYER — one SQLite file per guild
# =============================================================================
#
# Every guild gets its own file at guilds/{guild_id}.db. Hard isolation: no
# query can ever see another guild's data because each connection only opens
# that guild's file.
#
# When the bot leaves a guild (on_guild_remove), we delete the whole file.
# When a guild re-invites the bot later, a fresh DB is created. No ghost data.

def db_path(guild_id: int) -> Path:
    return DB_DIR / f"{guild_id}.db"


def db_connect(guild_id: int):
    """Open a connection to a specific guild's DB.
    Ensures the schema exists. Safe to call repeatedly — CREATE IF NOT EXISTS
    on every connection is cheap.

    WAL mode is enabled so the dashboard process can read/write the same
    database files concurrently with the bot. WAL is a per-database setting
    that persists across connections, so setting it every time is idempotent.

    busy_timeout makes SQLite wait up to 5 seconds for a lock instead of
    immediately raising 'database is locked' — important when the dashboard
    saves while the bot is mid-transaction.
    """
    path = db_path(guild_id)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn):
    """Create all tables if missing. Called on every connection open so new
    guilds auto-initialize. Cheap because CREATE IF NOT EXISTS is a no-op
    after the first call."""
    # --- Settings: the one row of config for this guild -----------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            -- singleton row keyed to 1; there's only ever one guild per file
            id                     INTEGER PRIMARY KEY CHECK (id = 1),
            verified_role_id       INTEGER,
            verify_channel_id      INTEGER,
            log_channel_id         INTEGER,
            captcha_length         INTEGER NOT NULL DEFAULT 6,
            cooldown_seconds       INTEGER NOT NULL DEFAULT 30,
            max_attempts           INTEGER NOT NULL DEFAULT 3,
            modal_timeout          INTEGER NOT NULL DEFAULT 300,
            patreon_role_ids       TEXT    NOT NULL DEFAULT '[]',
            admin_logs_enabled     INTEGER NOT NULL DEFAULT 1,
            invite_autodisable_threshold INTEGER NOT NULL DEFAULT 5,
            inviter_notifications  INTEGER NOT NULL DEFAULT 0,
            retention_months       INTEGER NOT NULL DEFAULT 12
        )
    """)
    # Ensure the singleton row exists
    conn.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")

    # --- Migration: add columns to older schemas if needed --------------
    existing = {row[1] for row in conn.execute("PRAGMA table_info(settings)")}
    migrations = [
        ("admin_logs_enabled", "INTEGER NOT NULL DEFAULT 1"),
        ("invite_autodisable_threshold", "INTEGER NOT NULL DEFAULT 5"),
        ("inviter_notifications", "INTEGER NOT NULL DEFAULT 0"),
        ("retention_months", "INTEGER NOT NULL DEFAULT 12"),
    ]
    for col, ddl in migrations:
        if col not in existing:
            conn.execute(f"ALTER TABLE settings ADD COLUMN {col} {ddl}")

    # --- Joins: permanent log of member joins with invite context -------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS joins (
            user_id        INTEGER NOT NULL,
            username       TEXT    NOT NULL,
            invite_code    TEXT,
            inviter_id     INTEGER,
            inviter_name   TEXT,
            channel_id     INTEGER,
            joined_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_joins_user ON joins(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_joins_inviter ON joins(inviter_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_joins_invite ON joins(invite_code)")

    # --- Bans: ban events with invite attribution at time of ban --------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bans (
            user_id               INTEGER NOT NULL,
            username              TEXT    NOT NULL,
            banned_at             TEXT    NOT NULL DEFAULT (datetime('now')),
            banned_by             TEXT,
            reason                TEXT,
            original_invite_code  TEXT,
            original_inviter_id   INTEGER,
            original_inviter_name TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_invite ON bans(original_invite_code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_inviter ON bans(original_inviter_id)")

    # --- Disabled invites: codes auto-disabled after too many bans ------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS disabled_invites (
            code                  TEXT PRIMARY KEY,
            disabled_at           TEXT NOT NULL DEFAULT (datetime('now')),
            ban_count             INTEGER NOT NULL,
            original_inviter_id   INTEGER,
            original_inviter_name TEXT
        )
    """)

    # --- Verifications: every successful verification, with method ------
    # Used by /stats for activity reporting. Method values:
    #   'captcha'      -- user solved a CAPTCHA
    #   'patreon'      -- auto-verified via Patreon tier role
    #   'grandfather'  -- bulk-verified via /grandfather
    # solve_seconds is only meaningful for 'captcha' (else NULL).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            user_id        INTEGER NOT NULL,
            username       TEXT    NOT NULL,
            verified_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            method         TEXT    NOT NULL,
            solve_seconds  INTEGER
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_verif_at ON verifications(verified_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_verif_method ON verifications(method)")

    # --- Kicks: tracks bot-initiated kicks (CAPTCHA failures, autodisable) ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kicks (
            user_id     INTEGER NOT NULL,
            username    TEXT    NOT NULL,
            kicked_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            reason      TEXT    NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_kicks_at ON kicks(kicked_at)")

    # --- Lockdown history: which channels has GateKeepr currently locked? -
    # Source of truth for /lockdown-undo. We INSERT a row per channel at
    # /lockdown time, DELETE it at /lockdown-undo time. Channel ID is the
    # primary key so re-running /lockdown is idempotent (no duplicates).
    # modified_role_ids is a JSON list of role IDs we set channel
    # overwrites for, so /lockdown-undo can remove the EXACT overwrites
    # we added (not just @everyone). is_verify_channel flips the meaning
    # of those overwrites (we set role denies on the verify channel
    # instead of allows).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS lockdown_history (
            channel_id        INTEGER PRIMARY KEY,
            locked_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            locked_by_user_id INTEGER,
            modified_role_ids TEXT    NOT NULL DEFAULT '[]',
            is_verify_channel INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Migration for older DBs where these columns didn't exist
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(lockdown_history)")}
    if "modified_role_ids" not in existing_cols:
        conn.execute("ALTER TABLE lockdown_history ADD COLUMN modified_role_ids TEXT NOT NULL DEFAULT '[]'")
    if "is_verify_channel" not in existing_cols:
        conn.execute("ALTER TABLE lockdown_history ADD COLUMN is_verify_channel INTEGER NOT NULL DEFAULT 0")

    conn.commit()


def delete_guild_db(guild_id: int):
    """Nuke a guild's entire database. Called when the bot leaves a guild
    so we don't accumulate orphaned data. Per-guild file means this is a
    one-line filesystem delete."""
    path = db_path(guild_id)
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass  # filesystem hiccup — worst case, file lingers; not harmful


def get_settings(guild_id: int) -> dict:
    """Fetch this guild's settings. The singleton row is guaranteed to exist
    because _ensure_schema() always creates it."""
    with db_connect(guild_id) as conn:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
    settings = dict(row)
    settings["patreon_role_ids"] = json.loads(settings["patreon_role_ids"] or "[]")
    return settings


def update_setting(guild_id: int, key: str, value):
    """Update a single setting for a guild. Row is guaranteed to exist.

    Reads back after write to catch silent failures (permissions, stale
    connections, whatever). If the readback doesn't match, prints loud
    diagnostic so it shows up in journalctl.
    """
    # Special handling for the JSON-stored list
    stored_value = value
    if key == "patreon_role_ids":
        stored_value = json.dumps(value)

    with db_connect(guild_id) as conn:
        cur = conn.execute(
            f"UPDATE settings SET {key} = ? WHERE id = 1", (stored_value,)
        )
        conn.commit()
        rows_changed = cur.rowcount
        # Read back in the SAME connection to verify persistence
        readback = conn.execute(
            f"SELECT {key} FROM settings WHERE id = 1"
        ).fetchone()

    if rows_changed != 1:
        print(
            f"[update_setting] guild={guild_id} key={key}: UPDATE affected "
            f"{rows_changed} rows (expected 1). Singleton row missing?",
            flush=True,
        )
    if readback is None or readback[key] != stored_value:
        print(
            f"[update_setting] guild={guild_id} key={key}: write didn't stick! "
            f"wrote={stored_value!r} read-back={readback[key] if readback else None!r}",
            flush=True,
        )
    else:
        print(
            f"[update_setting] guild={guild_id} key={key}={stored_value!r} OK",
            flush=True,
        )


def reset_settings(guild_id: int):
    """Wipe this guild's settings back to defaults.

    Three settings are deliberately preserved because they reflect admin
    intent about privacy/behavior that a reset shouldn't quietly override:
    - admin_logs_enabled (did they disable logging for a reason?)
    - inviter_notifications (opt-in; don't silently turn on)
    - retention_months (don't silently extend retention)
    """
    with db_connect(guild_id) as conn:
        preserved = conn.execute(
            "SELECT admin_logs_enabled, inviter_notifications, retention_months "
            "FROM settings WHERE id = 1"
        ).fetchone()
        conn.execute("DELETE FROM settings WHERE id = 1")
        conn.execute(
            "INSERT INTO settings "
            "(id, admin_logs_enabled, inviter_notifications, retention_months) "
            "VALUES (1, ?, ?, ?)",
            (
                preserved["admin_logs_enabled"],
                preserved["inviter_notifications"],
                preserved["retention_months"],
            ),
        )
        conn.commit()


# =============================================================================
# INVITE TRACKING DATA LAYER
# =============================================================================

def record_join(
    guild_id: int,
    user_id: int,
    username: str,
    invite_code: str | None,
    inviter_id: int | None,
    inviter_name: str | None,
    channel_id: int | None,
):
    """Log a member join with the invite they used (if identifiable)."""
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT INTO joins (user_id, username, invite_code, inviter_id, "
            "inviter_name, channel_id) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, username, invite_code, inviter_id, inviter_name, channel_id),
        )
        conn.commit()


def get_user_join_history(guild_id: int, user_id: int) -> list[dict]:
    """Return every join event for a user in this guild, most recent first.
    A user may have joined, left, and rejoined multiple times."""
    with db_connect(guild_id) as conn:
        rows = conn.execute(
            "SELECT * FROM joins WHERE user_id = ? ORDER BY joined_at DESC",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def record_ban(
    guild_id: int,
    user_id: int,
    username: str,
    banned_by: str | None,
    reason: str | None,
    original_invite_code: str | None,
    original_inviter_id: int | None,
    original_inviter_name: str | None,
):
    """Log a ban event along with the invite context captured at ban time."""
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT INTO bans (user_id, username, banned_by, reason, "
            "original_invite_code, original_inviter_id, original_inviter_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, username, banned_by, reason, original_invite_code,
             original_inviter_id, original_inviter_name),
        )
        conn.commit()


def record_verification(
    guild_id: int,
    user_id: int,
    username: str,
    method: str,
    solve_seconds: int | None = None,
):
    """Log a successful verification. Used by /stats.

    method: 'captcha' | 'patreon' | 'grandfather'
    solve_seconds: how long the user took to solve the CAPTCHA (only for 'captcha')
    """
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT INTO verifications (user_id, username, method, solve_seconds) "
            "VALUES (?, ?, ?, ?)",
            (user_id, username, method, solve_seconds),
        )
        conn.commit()


def record_kick(guild_id: int, user_id: int, username: str, reason: str):
    """Log a bot-initiated kick (failed CAPTCHA, joined via disabled invite, etc)."""
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT INTO kicks (user_id, username, reason) VALUES (?, ?, ?)",
            (user_id, username, reason),
        )
        conn.commit()


def record_lockdown(guild_id: int, channel_id: int, *,
                    locked_by_user_id: int,
                    modified_role_ids: list[int],
                    is_verify_channel: bool):
    """Mark a single channel as locked by GateKeepr. Idempotent — re-locking
    the same channel updates the timestamp and overwrites the role list,
    rather than duplicating. Used by /lockdown-undo as the source of truth
    for which overwrites to remove."""
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO lockdown_history "
            "(channel_id, locked_by_user_id, locked_at, "
            " modified_role_ids, is_verify_channel) "
            "VALUES (?, ?, datetime('now'), ?, ?)",
            (
                channel_id,
                locked_by_user_id,
                json.dumps([int(r) for r in modified_role_ids]),
                1 if is_verify_channel else 0,
            ),
        )
        conn.commit()


def get_locked_channel_ids(guild_id: int) -> list[int]:
    """Channels GateKeepr has locked in this guild. Used by /lockdown-undo."""
    with db_connect(guild_id) as conn:
        rows = conn.execute(
            "SELECT channel_id FROM lockdown_history"
        ).fetchall()
    return [r["channel_id"] for r in rows]


def get_lockdown_records(guild_id: int) -> list[dict]:
    """Full lockdown records — channel_id plus the role overwrites we set
    and whether it was the verify channel. Used by /lockdown-undo to remove
    every overwrite we added, not just the @everyone one."""
    with db_connect(guild_id) as conn:
        rows = conn.execute(
            "SELECT channel_id, modified_role_ids, is_verify_channel "
            "FROM lockdown_history"
        ).fetchall()
    out = []
    for r in rows:
        try:
            role_ids = json.loads(r["modified_role_ids"] or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            role_ids = []
        out.append({
            "channel_id": r["channel_id"],
            "modified_role_ids": [int(x) for x in role_ids if x is not None],
            "is_verify_channel": bool(r["is_verify_channel"]),
        })
    return out


def clear_lockdown_history(guild_id: int, channel_ids: list[int] | None = None):
    """Drop rows from lockdown_history. If channel_ids is None, clears the
    whole table. Otherwise only clears the listed channels."""
    with db_connect(guild_id) as conn:
        if channel_ids is None:
            conn.execute("DELETE FROM lockdown_history")
        elif channel_ids:
            placeholders = ",".join("?" * len(channel_ids))
            conn.execute(
                f"DELETE FROM lockdown_history WHERE channel_id IN ({placeholders})",
                channel_ids,
            )
        conn.commit()


def compute_stats(guild_id: int) -> dict:
    """Build the full stats dict for /stats. One DB connection, one trip.

    Returns counts for: lifetime, last 30 days, last 7 days, last 24 hours.
    Plus: method breakdown, average CAPTCHA solve time, currently disabled invites.
    """
    with db_connect(guild_id) as conn:
        def count_since(table, hours):
            row = conn.execute(
                f"SELECT COUNT(*) AS c FROM {table} "
                f"WHERE {('verified_at' if table == 'verifications' else 'kicked_at' if table == 'kicks' else 'joined_at' if table == 'joins' else 'banned_at')} "
                f">= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            return row["c"]

        def total(table):
            return conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]

        # Method breakdown
        methods = {
            row["method"]: row["c"]
            for row in conn.execute(
                "SELECT method, COUNT(*) AS c FROM verifications GROUP BY method"
            )
        }

        # Average CAPTCHA solve time (in seconds), only over rows where it was recorded
        avg_solve_row = conn.execute(
            "SELECT AVG(solve_seconds) AS avg_s FROM verifications "
            "WHERE method = 'captcha' AND solve_seconds IS NOT NULL"
        ).fetchone()
        avg_solve = avg_solve_row["avg_s"]

        # Disabled invites currently in effect
        disabled_count = conn.execute(
            "SELECT COUNT(*) AS c FROM disabled_invites"
        ).fetchone()["c"]

    return {
        "verifications": {
            "lifetime": total("verifications"),
            "last_30d": count_since("verifications", 24 * 30),
            "last_7d": count_since("verifications", 24 * 7),
            "last_24h": count_since("verifications", 24),
        },
        "joins": {
            "lifetime": total("joins"),
            "last_30d": count_since("joins", 24 * 30),
            "last_7d": count_since("joins", 24 * 7),
        },
        "kicks": {
            "lifetime": total("kicks"),
            "last_30d": count_since("kicks", 24 * 30),
            "last_7d": count_since("kicks", 24 * 7),
        },
        "bans": {
            "lifetime": total("bans"),
            "last_30d": count_since("bans", 24 * 30),
            "last_7d": count_since("bans", 24 * 7),
        },
        "method_breakdown": {
            "captcha": methods.get("captcha", 0),
            "patreon": methods.get("patreon", 0),
            "grandfather": methods.get("grandfather", 0),
        },
        "avg_solve_seconds": avg_solve,
        "disabled_invites": disabled_count,
    }


def ban_count_for_invite(guild_id: int, invite_code: str) -> int:
    """How many users who joined via this invite code have since been banned?"""
    with db_connect(guild_id) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM bans WHERE original_invite_code = ?",
            (invite_code,),
        ).fetchone()
    return row["c"]


def mark_invite_disabled(
    guild_id: int,
    code: str,
    ban_count: int,
    inviter_id: int | None,
    inviter_name: str | None,
):
    with db_connect(guild_id) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO disabled_invites "
            "(code, ban_count, original_inviter_id, original_inviter_name) "
            "VALUES (?, ?, ?, ?)",
            (code, ban_count, inviter_id, inviter_name),
        )
        conn.commit()


def inviter_stats(guild_id: int, inviter_id: int) -> dict:
    """Compute a reputation snapshot for an inviter.

    Returns counts: total invites (joins), bans, and per-invite breakdown.
    """
    with db_connect(guild_id) as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM joins WHERE inviter_id = ?", (inviter_id,)
        ).fetchone()["c"]
        banned = conn.execute(
            "SELECT COUNT(*) AS c FROM bans WHERE original_inviter_id = ?",
            (inviter_id,),
        ).fetchone()["c"]
        # Top invite codes by usage
        codes = conn.execute(
            "SELECT invite_code, COUNT(*) AS uses FROM joins "
            "WHERE inviter_id = ? AND invite_code IS NOT NULL "
            "GROUP BY invite_code ORDER BY uses DESC LIMIT 10",
            (inviter_id,),
        ).fetchall()
    return {
        "total_invited": total,
        "total_banned": banned,
        "top_codes": [dict(r) for r in codes],
    }


def audit_invite(guild_id: int, code: str) -> dict:
    """All joins via a given invite code, plus ban status for each."""
    with db_connect(guild_id) as conn:
        joins = conn.execute(
            "SELECT * FROM joins WHERE invite_code = ? ORDER BY joined_at DESC",
            (code,),
        ).fetchall()
        bans = conn.execute(
            "SELECT user_id FROM bans WHERE original_invite_code = ?", (code,)
        ).fetchall()
        disabled = conn.execute(
            "SELECT * FROM disabled_invites WHERE code = ?", (code,)
        ).fetchone()
    banned_ids = {r["user_id"] for r in bans}
    return {
        "joins": [dict(r) for r in joins],
        "banned_ids": banned_ids,
        "disabled": dict(disabled) if disabled else None,
    }


def invite_stats_summary(guild_id: int) -> dict:
    """Dashboard-style summary for /invite-stats."""
    with db_connect(guild_id) as conn:
        total_joins = conn.execute("SELECT COUNT(*) AS c FROM joins").fetchone()["c"]
        tracked_joins = conn.execute(
            "SELECT COUNT(*) AS c FROM joins WHERE invite_code IS NOT NULL"
        ).fetchone()["c"]
        total_bans = conn.execute("SELECT COUNT(*) AS c FROM bans").fetchone()["c"]
        disabled_count = conn.execute(
            "SELECT COUNT(*) AS c FROM disabled_invites"
        ).fetchone()["c"]
        top_inviters = conn.execute(
            "SELECT inviter_id, inviter_name, COUNT(*) AS c FROM joins "
            "WHERE inviter_id IS NOT NULL "
            "GROUP BY inviter_id ORDER BY c DESC LIMIT 10"
        ).fetchall()
    return {
        "total_joins": total_joins,
        "tracked_joins": tracked_joins,
        "total_bans": total_bans,
        "disabled_count": disabled_count,
        "top_inviters": [dict(r) for r in top_inviters],
    }


def clear_tracking_data(guild_id: int) -> dict:
    """Wipe joins/bans/disabled_invites but keep settings.
    Returns counts of what was deleted, for the log message."""
    with db_connect(guild_id) as conn:
        j = conn.execute("SELECT COUNT(*) AS c FROM joins").fetchone()["c"]
        b = conn.execute("SELECT COUNT(*) AS c FROM bans").fetchone()["c"]
        d = conn.execute("SELECT COUNT(*) AS c FROM disabled_invites").fetchone()["c"]
        conn.execute("DELETE FROM joins")
        conn.execute("DELETE FROM bans")
        conn.execute("DELETE FROM disabled_invites")
        conn.commit()
    return {"joins": j, "bans": b, "disabled": d}


def prune_old_records(guild_id: int, months: int) -> int:
    """Delete join records older than N months. Called by the daily sweep.
    Bans are kept forever (mods usually want permanent ban records)."""
    with db_connect(guild_id) as conn:
        cur = conn.execute(
            "DELETE FROM joins WHERE joined_at < datetime('now', ?)",
            (f'-{months} months',),
        )
        conn.commit()
        return cur.rowcount


def export_all_data(guild_id: int) -> dict:
    """Serialize everything in the guild's DB to a plain-Python dict.
    Used by /export-data to hand admins a JSON download."""
    with db_connect(guild_id) as conn:
        settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        joins = conn.execute("SELECT * FROM joins ORDER BY joined_at DESC").fetchall()
        bans = conn.execute("SELECT * FROM bans ORDER BY banned_at DESC").fetchall()
        disabled = conn.execute("SELECT * FROM disabled_invites").fetchall()
    settings_dict = dict(settings_row)
    settings_dict["patreon_role_ids"] = json.loads(settings_dict.get("patreon_role_ids") or "[]")
    return {
        "guild_id": guild_id,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "settings": settings_dict,
        "joins": [dict(r) for r in joins],
        "bans": [dict(r) for r in bans],
        "disabled_invites": [dict(r) for r in disabled],
    }


# =============================================================================
# BOT SETUP
# =============================================================================

intents = discord.Intents.default()
intents.members = True  # needed for role changes and member iteration
bot = commands.Bot(command_prefix="!", intents=intents)

# In-memory state (resets on restart, which is fine):
# Keyed by (guild_id, user_id) so the same user in different servers is separate.
pending_captchas = {}    # (guild_id, user_id) -> correct CAPTCHA text
last_attempt_time = {}   # (guild_id, user_id) -> unix timestamp
failed_attempts = {}     # (guild_id, user_id) -> consecutive failed count
captcha_interactions = {}  # (guild_id, user_id) -> the discord.Interaction that sent the CAPTCHA
                          # (needed so we can delete the CAPTCHA image after the user fails)
captcha_started_at = {}  # (guild_id, user_id) -> unix timestamp the CAPTCHA was issued
                         # (used to compute solve time for /stats)


# =============================================================================
# HELPERS
# =============================================================================

def generate_captcha(length: int):
    """Create a distorted CAPTCHA image. Returns (text, image_buffer)."""
    text = "".join(random.choices(CAPTCHA_CHARSET, k=length))
    image = ImageCaptcha(width=280, height=90)
    buffer = io.BytesIO()
    image.write(text, buffer)
    buffer.seek(0)
    return text, buffer


async def log_event(guild: discord.Guild, message: str, color=discord.Color.blue()):
    """Post an event to a guild's configured log channel, if any."""
    settings = get_settings(guild.id)
    log_id = settings.get("log_channel_id")
    if not log_id:
        return
    channel = guild.get_channel(log_id)
    if channel is None:
        print(
            f"[log_event] guild {guild.id}: log_channel_id={log_id} set but "
            f"channel not found (deleted? cache not ready?)",
            flush=True,
        )
        return
    embed = discord.Embed(description=message, color=color, timestamp=datetime.utcnow())
    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        print(
            f"[log_event] guild {guild.id}: Forbidden posting to "
            f"#{channel.name} ({channel.id}). Bot needs View Channel, "
            f"Send Messages, Embed Links.",
            flush=True,
        )
    except discord.HTTPException as e:
        print(f"[log_event] guild {guild.id}: HTTPException: {e}", flush=True)


async def admin_log(interaction: discord.Interaction, action: str, details: str = ""):
    """Log an admin command use to the guild's log channel, if enabled.

    Called at the top of every admin slash command. Respects the per-guild
    admin_logs_enabled setting so servers can turn this off.

    Example output:
        🛠️ **Alice** (`12345`) used `/set-verified-role` → set to @Verified
    """
    if interaction.guild is None:
        return
    settings = get_settings(interaction.guild.id)
    if not settings.get("admin_logs_enabled"):
        return

    msg = f"🛠️ **{interaction.user}** (`{interaction.user.id}`) used `/{action}`"
    if details:
        msg += f" — {details}"
    await log_event(interaction.guild, msg, color=discord.Color.dark_gray())


def is_configured(settings: dict):
    """Check if a guild has the minimum required settings to run verification.
    Returns (is_ok, error_message)."""
    if not settings.get("verified_role_id"):
        return False, (
            "⚠️ This server hasn't set a Verified role yet. "
            "An admin needs to run `/config set-verified-role`."
        )
    if not settings.get("verify_channel_id"):
        return False, (
            "⚠️ This server hasn't set a verify channel yet. "
            "An admin needs to run `/config set-verify-channel`."
        )
    return True, ""


# =============================================================================
# VERIFICATION UI (buttons + modal)
# =============================================================================

class AnswerModal(discord.ui.Modal, title="Enter CAPTCHA"):
    """Popup form where the user types what they saw in the image."""

    def __init__(self, captcha_length: int):
        super().__init__()
        self.answer = discord.ui.TextInput(
            label="Type the characters from the image",
            min_length=captcha_length,
            max_length=captcha_length,
            placeholder="Not case-sensitive",
        )
        self.add_item(self.answer)

    async def on_submit(self, interaction: discord.Interaction):
        user = interaction.user
        guild = interaction.guild
        key = (guild.id, user.id)
        correct = pending_captchas.get(key)
        settings = get_settings(guild.id)

        if not correct:
            await interaction.response.send_message(
                "⚠️ This CAPTCHA expired. Click **Verify** to get a new one.",
                ephemeral=True,
            )
            return

        # Helper: delete the original CAPTCHA image message so it doesn't
        # linger after a success or failure.
        async def delete_captcha_message():
            captcha_inter = captcha_interactions.pop(key, None)
            if captcha_inter is not None:
                try:
                    await captcha_inter.delete_original_response()
                except (discord.NotFound, discord.HTTPException):
                    # Message already gone or can't be deleted -- ignore.
                    pass

        # Correct answer
        if self.answer.value.strip().upper() == correct:
            # Compute solve time before we clear state
            started = captcha_started_at.pop(key, None)
            solve_seconds = int(time.time() - started) if started else None

            pending_captchas.pop(key, None)
            failed_attempts.pop(key, None)
            await delete_captcha_message()

            role = guild.get_role(settings["verified_role_id"])
            if role is None:
                await interaction.response.send_message(
                    "⚠️ The Verified role is missing. Please contact a moderator.",
                    ephemeral=True,
                )
                return
            try:
                await user.add_roles(role, reason="Passed CAPTCHA verification")
            except discord.Forbidden:
                await interaction.response.send_message(
                    "⚠️ I don't have permission to assign the Verified role. "
                    "An admin needs to put my role above Verified in Server Settings.",
                    ephemeral=True,
                )
                return

            # Record for /stats
            record_verification(
                guild.id, user.id, str(user), "captcha", solve_seconds
            )

            await interaction.response.send_message(
                "✅ Verified! Welcome to the server.", ephemeral=True
            )
            await log_event(
                guild,
                f"✅ **{user}** (`{user.id}`) verified successfully.",
                color=discord.Color.green(),
            )
            return

        # Wrong answer -- always delete the CAPTCHA image regardless of what
        # happens next (kick or retry), so they start fresh.
        pending_captchas.pop(key, None)
        await delete_captcha_message()
        attempts = failed_attempts.get(key, 0) + 1
        failed_attempts[key] = attempts
        max_attempts = settings["max_attempts"]

        if max_attempts and attempts >= max_attempts:
            await interaction.response.send_message(
                f"❌ Too many failed attempts ({attempts}). You will be removed. "
                "You can rejoin and try again.",
                ephemeral=True,
            )
            await log_event(
                guild,
                f"🚪 **{user}** (`{user.id}`) kicked after {attempts} failed CAPTCHAs.",
                color=discord.Color.red(),
            )
            try:
                await user.kick(reason=f"Failed CAPTCHA {attempts} times")
                record_kick(guild.id, user.id, str(user), f"Failed CAPTCHA {attempts} times")
            except discord.Forbidden:
                pass
            failed_attempts.pop(key, None)
            captcha_started_at.pop(key, None)
            return

        remaining = "" if not max_attempts else f" ({max_attempts - attempts} attempt(s) left)"
        # The "❌ Incorrect" message is ephemeral; Discord auto-dismisses it
        # when the user interacts elsewhere (e.g. clicks Verify again), so
        # it acts as a transient notice without cluttering the channel.
        await interaction.response.send_message(
            f"❌ Incorrect.{remaining} Click **Verify** again for a new CAPTCHA.",
            ephemeral=True,
        )
        await log_event(
            guild,
            f"❌ **{user}** (`{user.id}`) failed CAPTCHA (attempt {attempts}).",
            color=discord.Color.orange(),
        )


class OpenModalView(discord.ui.View):
    """'Enter Answer' button that opens the modal."""

    def __init__(self, captcha_length: int, modal_timeout: int):
        super().__init__(timeout=modal_timeout)
        self.captcha_length = captcha_length

    @discord.ui.button(label="Enter Answer", style=discord.ButtonStyle.primary)
    async def open_modal(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(AnswerModal(self.captcha_length))


class VerifyView(discord.ui.View):
    """The permanent 'Verify' button in each server's verify channel."""

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Verify",
        style=discord.ButtonStyle.success,
        custom_id="verify_start",  # must stay constant for persistence
    )
    async def verify(self, interaction: discord.Interaction, button: discord.ui.Button):
        user = interaction.user
        guild = interaction.guild
        key = (guild.id, user.id)
        settings = get_settings(guild.id)

        ok, err = is_configured(settings)
        if not ok:
            await interaction.response.send_message(err, ephemeral=True)
            return

        role = guild.get_role(settings["verified_role_id"])
        if role and role in user.roles:
            await interaction.response.send_message(
                "You're already verified.", ephemeral=True
            )
            return

        now = time.time()
        last = last_attempt_time.get(key, 0)
        if now - last < settings["cooldown_seconds"]:
            wait = int(settings["cooldown_seconds"] - (now - last))
            await interaction.response.send_message(
                f"⏳ Please wait {wait} more second(s) before trying again.",
                ephemeral=True,
            )
            return
        last_attempt_time[key] = now

        # If the user has a lingering CAPTCHA from a previous click, delete
        # its image so they don't end up with two CAPTCHA messages visible.
        old_interaction = captcha_interactions.pop(key, None)
        if old_interaction is not None:
            try:
                await old_interaction.delete_original_response()
            except (discord.NotFound, discord.HTTPException):
                pass
        # Also clear any stale pending answer so the old CAPTCHA's solution
        # can't be used against the new image.
        pending_captchas.pop(key, None)

        text, buffer = generate_captcha(settings["captcha_length"])
        pending_captchas[key] = text
        captcha_started_at[key] = time.time()
        file = discord.File(buffer, filename="captcha.png")

        await interaction.response.send_message(
            "🔐 Solve the CAPTCHA below, then click **Enter Answer**.\n"
            "*(Not case-sensitive. Only you can see this message.)*",
            file=file,
            view=OpenModalView(settings["captcha_length"], settings["modal_timeout"]),
            ephemeral=True,
        )
        # Save this interaction so we can delete the CAPTCHA image message
        # if the user enters a wrong answer or requests another one.
        captcha_interactions[key] = interaction
        await log_event(
            guild,
            f"🔔 **{user}** (`{user.id}`) started verification.",
            color=discord.Color.blue(),
        )


# =============================================================================
# EVENTS
# =============================================================================

# In-memory invite cache: {guild_id: {invite_code: uses_count}}
# We only need the uses count to diff on member join. Inviter info is
# looked up live from Discord at join time.
invite_cache: dict[int, dict[str, int]] = {}


async def refresh_invite_cache(guild: discord.Guild):
    """Populate the cache for one guild. Called on startup and whenever
    we suspect the cache is stale (e.g. after on_invite_create/delete)."""
    try:
        invites = await guild.invites()
        invite_cache[guild.id] = {inv.code: inv.uses for inv in invites}
    except discord.Forbidden:
        # Bot lacks Manage Server — invite tracking simply won't work for
        # this guild. Not fatal; other features continue to function.
        invite_cache[guild.id] = {}
    except discord.HTTPException:
        invite_cache[guild.id] = {}


@bot.event
async def on_ready():
    bot.add_view(VerifyView())
    # Prime invite caches for every guild we're currently in
    for g in bot.guilds:
        await refresh_invite_cache(g)
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} slash commands.")
    except Exception as e:
        print(f"Failed to sync slash commands: {e}")
    # Start the daily retention sweep
    if not retention_sweep.is_running():
        retention_sweep.start()
    # Start the public status JSON writer
    if not status_writer.is_running():
        status_writer.start()
    print(f"Logged in as {bot.user} (id: {bot.user.id}) — serving {len(bot.guilds)} guilds")


@bot.event
async def on_guild_join(guild: discord.Guild):
    """A new server invited the bot. First settings read auto-creates the DB."""
    get_settings(guild.id)
    await refresh_invite_cache(guild)
    print(f"Joined new guild: {guild.name} ({guild.id})")


@bot.event
async def on_guild_remove(guild: discord.Guild):
    """Bot was kicked or the guild was deleted. Nuke this guild's DB
    entirely — no orphaned data, no ghost records."""
    delete_guild_db(guild.id)
    invite_cache.pop(guild.id, None)
    print(f"Left guild: {guild.name} ({guild.id}) — data wiped")


@bot.event
async def on_invite_create(invite: discord.Invite):
    if invite.guild:
        invite_cache.setdefault(invite.guild.id, {})[invite.code] = invite.uses


@bot.event
async def on_invite_delete(invite: discord.Invite):
    if invite.guild:
        invite_cache.get(invite.guild.id, {}).pop(invite.code, None)


@bot.event
async def on_member_join(member: discord.Member):
    """Record which invite the user joined through, log it, and persist.

    Algorithm: Discord doesn't tell us directly which invite was used.
    We compare our cached uses-counts against Discord's current counts
    — whichever invite's count went up by 1 (or more) is the one used.

    Edge cases handled:
    - Two joins in rapid succession: both get attributed to the same
      invite if only one count diff is found. Accepted imprecision.
    - Bot restarted with no cache: first joiner logged as "unknown invite"
      until cache is rebuilt.
    - Vanity URL: tracked separately if guild.vanity_url_code is set.
    """
    guild = member.guild
    used_code = None
    inviter_id = None
    inviter_name = None
    channel_id = None

    try:
        current = await guild.invites()
        cached = invite_cache.get(guild.id, {})

        # Find any invite whose uses went up
        for inv in current:
            if inv.uses > cached.get(inv.code, 0):
                used_code = inv.code
                if inv.inviter:
                    inviter_id = inv.inviter.id
                    inviter_name = str(inv.inviter)
                channel_id = inv.channel.id if inv.channel else None
                break

        # Update cache with latest values
        invite_cache[guild.id] = {inv.code: inv.uses for inv in current}

        # Vanity URL check — only matters if we found no regular invite diff
        if used_code is None and guild.vanity_url_code:
            try:
                vanity = await guild.vanity_invite()
                if vanity:
                    # We can't diff vanity uses easily, but if no regular
                    # invite matched, assume vanity. Best effort.
                    used_code = f"(vanity:{guild.vanity_url_code})"
            except (discord.Forbidden, discord.HTTPException):
                pass
    except discord.Forbidden:
        # No Manage Server — tracking unavailable. Still record the join
        # so the admin's export data shows who joined when.
        pass
    except discord.HTTPException:
        pass

    # Block joiners from invites we've auto-disabled (defense in depth —
    # Discord should prevent this once we delete the invite, but if the
    # delete hadn't propagated yet, we catch it here)
    if used_code:
        with db_connect(guild.id) as conn:
            row = conn.execute(
                "SELECT 1 FROM disabled_invites WHERE code = ?", (used_code,)
            ).fetchone()
        if row:
            try:
                await member.kick(reason="Joined via auto-disabled invite")
                record_kick(guild.id, member.id, str(member),
                            f"Joined via auto-disabled invite {used_code}")
                await log_event(
                    guild,
                    f"🚫 Kicked **{member}** — joined via auto-disabled invite `{used_code}`.",
                    color=discord.Color.red(),
                )
                return
            except discord.Forbidden:
                pass

    # Persist the join
    record_join(
        guild.id,
        member.id,
        str(member),
        used_code,
        inviter_id,
        inviter_name,
        channel_id,
    )

    # Log it nicely to the log channel
    if used_code:
        if inviter_name:
            msg = (
                f"👋 **{member}** (`{member.id}`) joined via invite "
                f"`{used_code}` — created by **{inviter_name}** (`{inviter_id}`)."
            )
        else:
            msg = f"👋 **{member}** (`{member.id}`) joined via `{used_code}`."
    else:
        msg = (
            f"👋 **{member}** (`{member.id}`) joined — "
            f"invite source could not be determined."
        )
    await log_event(guild, msg, color=discord.Color.blurple())


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    """When a user is banned, surface their invite history in the log and
    consider auto-disabling the invite they came from."""
    # Pull their most recent join record, if any
    history = get_user_join_history(guild.id, user.id)
    latest = history[0] if history else None

    # Try to read who did the ban + reason from the audit log
    banned_by = None
    reason = None
    try:
        await asyncio.sleep(1)  # audit log is eventually consistent
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.ban):
            if entry.target and entry.target.id == user.id:
                banned_by = str(entry.user) if entry.user else None
                reason = entry.reason
                break
    except discord.Forbidden:
        pass

    # Persist ban record with captured invite context (if any)
    record_ban(
        guild.id,
        user.id,
        str(user),
        banned_by,
        reason,
        latest["invite_code"] if latest else None,
        latest["inviter_id"] if latest else None,
        latest["inviter_name"] if latest else None,
    )

    # Build the log embed
    lines = [f"🔨 **BAN** — {user} (`{user.id}`)"]
    if banned_by:
        lines.append(f"Banned by: **{banned_by}**")
    if reason:
        lines.append(f"Reason: {reason}")
    lines.append("")  # spacer
    if latest and latest["invite_code"]:
        lines.append(f"Originally joined: `{latest['joined_at']}`")
        lines.append(f"Via invite: `{latest['invite_code']}`")
        if latest["inviter_name"]:
            lines.append(
                f"Created by: **{latest['inviter_name']}** "
                f"(`{latest['inviter_id']}`)"
            )
    elif latest:
        lines.append(f"Originally joined: `{latest['joined_at']}`")
        lines.append("Invite source was not tracked.")
    else:
        lines.append("No join history on record (joined before tracking began).")
    await log_event(guild, "\n".join(lines), color=discord.Color.red())

    # --- Auto-disable threshold check -----------------------------------
    if not latest or not latest["invite_code"] or latest["invite_code"].startswith("("):
        return  # nothing to disable — no code, or vanity

    settings = get_settings(guild.id)
    threshold = settings.get("invite_autodisable_threshold", 5)
    if threshold <= 0:
        return  # feature disabled

    code = latest["invite_code"]
    count = ban_count_for_invite(guild.id, code)

    if count >= threshold:
        # Check if we've already disabled this invite — don't spam logs
        with db_connect(guild.id) as conn:
            already = conn.execute(
                "SELECT 1 FROM disabled_invites WHERE code = ?", (code,)
            ).fetchone()
        if not already:
            # Delete the invite via Discord API
            try:
                inv = next(
                    (i for i in await guild.invites() if i.code == code), None
                )
                if inv:
                    await inv.delete(
                        reason=f"Auto-disabled: {count} bans from this invite"
                    )
            except (discord.Forbidden, discord.HTTPException, discord.NotFound):
                pass
            mark_invite_disabled(
                guild.id, code, count,
                latest["inviter_id"], latest["inviter_name"],
            )
            await log_event(
                guild,
                f"🛡️ Auto-disabled invite `{code}` — {count} bans from this "
                f"code (threshold: {threshold}).",
                color=discord.Color.orange(),
            )

    # --- Inviter DM notification (opt-in) -------------------------------
    if settings.get("inviter_notifications") and latest["inviter_id"]:
        inviter = guild.get_member(latest["inviter_id"])
        if inviter:
            try:
                await inviter.send(
                    f"Heads up — **{user}**, who you invited to "
                    f"**{guild.name}**, was just banned. This is an "
                    f"automated notification you can disable by asking a "
                    f"server admin to turn off inviter notifications."
                )
            except (discord.Forbidden, discord.HTTPException):
                pass  # DMs closed or other issue


# =============================================================================
# BACKGROUND TASKS
# =============================================================================

@tasks.loop(hours=24)
async def retention_sweep():
    """Once per day, walk all guilds and prune join records older than
    their configured retention period. Ban records are kept forever."""
    for guild in bot.guilds:
        try:
            settings = get_settings(guild.id)
            months = settings.get("retention_months", 12)
            if months > 0:
                pruned = prune_old_records(guild.id, months)
                if pruned:
                    print(f"Pruned {pruned} old joins from guild {guild.id}")
        except Exception as e:
            print(f"Retention sweep failed for guild {guild.id}: {e}")


def compute_global_stats() -> dict:
    """Aggregate verification counts across every guild the bot serves.

    Walks every guild SQLite file. For 1-100 guilds this is cheap (a few ms
    total). For thousands we'd want caching, but we'll cross that bridge if
    we get there.
    """
    total_verifications = 0
    verifications_24h = 0
    total_servers = len(bot.guilds)

    for guild in bot.guilds:
        try:
            with db_connect(guild.id) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM verifications"
                ).fetchone()
                total_verifications += row["c"]
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM verifications "
                    "WHERE verified_at >= datetime('now', '-24 hours')"
                ).fetchone()
                verifications_24h += row["c"]
        except Exception as e:
            # A single guild's DB failing shouldn't break the whole stats
            # endpoint -- just log and skip.
            print(f"[global_stats] guild {guild.id} skipped: {e}", flush=True)

    return {
        "total_servers": total_servers,
        "total_verifications": total_verifications,
        "verifications_24h": verifications_24h,
    }


@tasks.loop(seconds=STATUS_WRITE_INTERVAL_SECONDS)
async def status_writer():
    """Periodically write status.json so the website can show live data.

    Writes atomically: dump to a .tmp file, then rename. This way the
    website never reads a half-written file.
    """
    try:
        global_stats = compute_global_stats()
        payload = {
            "online": True,
            "version": "1.5",  # bump this when you ship breaking changes
            "uptime_seconds": int(time.time() - BOT_STARTED_AT),
            "last_updated": datetime.utcnow().isoformat() + "Z",
            **global_stats,
        }

        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_FILE.with_suffix(STATUS_FILE.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(STATUS_FILE)
    except PermissionError as e:
        # Probably running as a non-root user without write access to /var/www.
        # Log once, then keep trying every interval -- maybe someone fixes it.
        print(f"[status_writer] permission denied writing {STATUS_FILE}: {e}",
              flush=True)
    except Exception as e:
        print(f"[status_writer] failed: {e}", flush=True)


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Detect Patreon role assignments and auto-verify."""
    settings = get_settings(after.guild.id)
    patreon_ids = settings.get("patreon_role_ids", [])
    if not patreon_ids:
        return

    before_ids = {r.id for r in before.roles}
    after_ids = {r.id for r in after.roles}
    added_ids = after_ids - before_ids

    if not any(rid in patreon_ids for rid in added_ids):
        return

    verified_id = settings.get("verified_role_id")
    if not verified_id:
        return

    verified_role = after.guild.get_role(verified_id)
    if verified_role is None or verified_role in after.roles:
        return

    try:
        await after.add_roles(verified_role, reason="Auto-verified via Patreon tier")
        record_verification(after.guild.id, after.id, str(after), "patreon")
        await log_event(
            after.guild,
            f"💜 **{after}** (`{after.id}`) auto-verified via Patreon role.",
            color=discord.Color.purple(),
        )
    except discord.Forbidden:
        await log_event(
            after.guild,
            f"⚠️ Couldn't auto-verify **{after}** — check role hierarchy.",
            color=discord.Color.red(),
        )


# =============================================================================
# SLASH COMMANDS -- /setup-verify and /grandfather
# =============================================================================

@bot.tree.command(name="setup-verify", description="Post the permanent Verify button in this channel.")
@app_commands.default_permissions(administrator=True)
async def setup_verify(interaction: discord.Interaction):
    settings = get_settings(interaction.guild.id)
    ok, err = is_configured(settings)
    if not ok:
        await interaction.response.send_message(err, ephemeral=True)
        return

    # Post to the channel set in /config set-verify-channel, NOT the channel
    # where this command was run. This way admins can run /setup-verify from
    # anywhere (e.g. a mod channel) and the button still lands in the right place.
    verify_channel = interaction.guild.get_channel(settings["verify_channel_id"])
    if verify_channel is None:
        await interaction.response.send_message(
            "⚠️ The configured verify channel no longer exists. "
            "Re-run `/config set-verify-channel` to fix it.",
            ephemeral=True,
        )
        return

    # Check the bot can actually post there
    perms = verify_channel.permissions_for(interaction.guild.me)
    if not (perms.send_messages and perms.embed_links):
        await interaction.response.send_message(
            f"⚠️ I don't have permission to post in {verify_channel.mention}. "
            "Please give me **Send Messages** and **Embed Links** there.",
            ephemeral=True,
        )
        return

    embed = discord.Embed(
        title="🔒 Server Verification",
        description=(
            "Welcome! To access the rest of the server, click the **Verify** "
            "button below and solve a quick CAPTCHA.\n\n"
            "This keeps bots and spammers out — thanks for your patience!"
        ),
        color=discord.Color.green(),
    )
    await verify_channel.send(embed=embed, view=VerifyView())
    await interaction.response.send_message(
        f"✅ Verify button posted in {verify_channel.mention}.", ephemeral=True
    )
    await admin_log(interaction, "setup-verify", f"posted button in {verify_channel.mention}")


@bot.tree.command(name="grandfather", description="Grant Verified to all existing members (run before locking channels).")
@app_commands.default_permissions(administrator=True)
async def grandfather(interaction: discord.Interaction):
    settings = get_settings(interaction.guild.id)
    guild = interaction.guild
    role_id = settings.get("verified_role_id")
    if not role_id:
        await interaction.response.send_message(
            "⚠️ Set a Verified role first with `/config set-verified-role`.",
            ephemeral=True,
        )
        return

    role = guild.get_role(role_id)
    if role is None:
        await interaction.response.send_message(
            "⚠️ The configured Verified role no longer exists. Please reconfigure.",
            ephemeral=True,
        )
        return

    if role >= guild.me.top_role:
        await interaction.response.send_message(
            "⚠️ My role must be above the Verified role in Server Settings.",
            ephemeral=True,
        )
        return

    await interaction.response.send_message(
        f"⏳ Starting grandfather pass on ~{guild.member_count} members. "
        "This may take a while on larger servers.",
        ephemeral=True,
    )

    granted = skipped_bot = skipped_had = failed = 0
    for member in guild.members:
        if member.bot:
            skipped_bot += 1
        elif role in member.roles:
            skipped_had += 1
        else:
            try:
                await member.add_roles(role, reason="Grandfathered before CAPTCHA rollout")
                record_verification(guild.id, member.id, str(member), "grandfather")
                granted += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1

    await interaction.followup.send(
        f"✅ **Grandfather pass complete.**\n"
        f"• Granted: **{granted}**\n"
        f"• Already had it: **{skipped_had}**\n"
        f"• Bots skipped: **{skipped_bot}**\n"
        f"• Failed: **{failed}**",
        ephemeral=True,
    )
    await log_event(
        guild,
        f"🎟️ Grandfather pass by **{interaction.user}**: "
        f"{granted} granted, {skipped_had} already had, "
        f"{skipped_bot} bots, {failed} failed.",
        color=discord.Color.gold(),
    )


# =============================================================================
# SLASH COMMANDS -- flat config commands (no /config prefix)
# =============================================================================

@bot.tree.command(name="settings", description="Show current verification settings for this server.")
@app_commands.default_permissions(administrator=True)
async def settings_view(interaction: discord.Interaction):
    s = get_settings(interaction.guild.id)
    guild = interaction.guild

    def describe_role(rid):
        if not rid:
            return "*(not set)*"
        r = guild.get_role(rid)
        return r.mention if r else f"*(deleted role {rid})*"

    def describe_channel(cid):
        if not cid:
            return "*(not set)*"
        c = guild.get_channel(cid)
        return c.mention if c else f"*(deleted channel {cid})*"

    patreon_mentions = (
        ", ".join(describe_role(rid) for rid in s["patreon_role_ids"])
        if s["patreon_role_ids"] else "*(none)*"
    )

    embed = discord.Embed(title="Verification Settings", color=discord.Color.purple())
    embed.add_field(name="Verified role", value=describe_role(s["verified_role_id"]), inline=False)
    embed.add_field(name="Verify channel", value=describe_channel(s["verify_channel_id"]), inline=False)
    embed.add_field(name="Log channel", value=describe_channel(s["log_channel_id"]), inline=False)
    embed.add_field(name="CAPTCHA length", value=s["captcha_length"], inline=True)
    embed.add_field(name="Cooldown (sec)", value=s["cooldown_seconds"], inline=True)
    embed.add_field(name="Max attempts", value=s["max_attempts"] or "Unlimited", inline=True)
    embed.add_field(name="Modal timeout (sec)", value=s["modal_timeout"], inline=True)
    embed.add_field(name="Patreon tier roles", value=patreon_mentions, inline=False)
    embed.add_field(name="Admin logs", value="Enabled" if s.get("admin_logs_enabled") else "Disabled", inline=True)

    # Invite tracking settings
    autodisable = s.get("invite_autodisable_threshold", 5)
    embed.add_field(
        name="Invite auto-disable",
        value=("Off" if autodisable == 0 else f"After {autodisable} bans"),
        inline=True,
    )
    embed.add_field(
        name="Inviter DM on ban",
        value="Enabled" if s.get("inviter_notifications") else "Disabled",
        inline=True,
    )
    retention = s.get("retention_months", 12)
    embed.add_field(
        name="Join retention",
        value=("Forever" if retention == 0 else f"{retention} months"),
        inline=True,
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)
    await admin_log(interaction, "settings", "viewed settings")


@bot.tree.command(name="stats", description="Show verification activity stats for this server.")
@app_commands.default_permissions(administrator=True)
async def stats(interaction: discord.Interaction):
    s = compute_stats(interaction.guild.id)
    v = s["verifications"]
    j = s["joins"]
    k = s["kicks"]
    b = s["bans"]
    m = s["method_breakdown"]

    # Verification rate: of people who joined in last 30d, how many got verified?
    rate = ""
    if j["last_30d"] > 0:
        pct = (v["last_30d"] / j["last_30d"]) * 100
        rate = f" ({pct:.0f}% of joiners)"

    # Average solve time
    if s["avg_solve_seconds"] is not None:
        avg = s["avg_solve_seconds"]
        if avg < 60:
            solve_str = f"{avg:.1f} seconds"
        else:
            solve_str = f"{avg / 60:.1f} minutes"
    else:
        solve_str = "*(no CAPTCHA solves yet)*"

    embed = discord.Embed(
        title="📊 GateKeepr Stats",
        description=f"Activity for **{interaction.guild.name}**",
        color=discord.Color.purple(),
    )

    embed.add_field(
        name="✅ Verifications",
        value=(
            f"**Last 24h:** {v['last_24h']}\n"
            f"**Last 7d:** {v['last_7d']}\n"
            f"**Last 30d:** {v['last_30d']}{rate}\n"
            f"**Lifetime:** {v['lifetime']}"
        ),
        inline=True,
    )

    embed.add_field(
        name="🚪 Joins",
        value=(
            f"**Last 7d:** {j['last_7d']}\n"
            f"**Last 30d:** {j['last_30d']}\n"
            f"**Lifetime:** {j['lifetime']}"
        ),
        inline=True,
    )

    embed.add_field(
        name="\u200b",  # Empty field for layout
        value="\u200b",
        inline=True,
    )

    embed.add_field(
        name="🥷 By method",
        value=(
            f"**CAPTCHA:** {m['captcha']}\n"
            f"**Patreon auto:** {m['patreon']}\n"
            f"**Grandfathered:** {m['grandfather']}"
        ),
        inline=True,
    )

    embed.add_field(
        name="❌ Removals",
        value=(
            f"**Kicks (30d):** {k['last_30d']}\n"
            f"**Kicks (lifetime):** {k['lifetime']}\n"
            f"**Bans (lifetime):** {b['lifetime']}"
        ),
        inline=True,
    )

    embed.add_field(
        name="\u200b",
        value="\u200b",
        inline=True,
    )

    embed.add_field(
        name="⏱️ Avg CAPTCHA solve",
        value=solve_str,
        inline=True,
    )

    embed.add_field(
        name="🚫 Disabled invites",
        value=str(s["disabled_invites"]),
        inline=True,
    )

    embed.set_footer(text="Stats are tracked from the moment this version of the bot is deployed.")
    await interaction.response.send_message(embed=embed, ephemeral=True)
    await admin_log(interaction, "stats", "viewed stats")


@bot.tree.command(name="set-verified-role", description="Set the role granted upon successful verification.")
@app_commands.default_permissions(administrator=True)
async def set_verified_role(interaction: discord.Interaction, role: discord.Role):
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message(
            f"⚠️ I can't manage {role.mention} because my role isn't above it. "
            "Drag my role higher in Server Settings -> Roles, then try again.",
            ephemeral=True,
        )
        return
    update_setting(interaction.guild.id, "verified_role_id", role.id)
    await interaction.response.send_message(
        f"✅ Verified role set to {role.mention}.", ephemeral=True
    )
    await admin_log(interaction, "set-verified-role", f"set to {role.mention}")


@bot.tree.command(name="set-verify-channel", description="Set the channel where the Verify button lives.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(channel="Any text channel the bot can post in.")
async def set_verify_channel(
    interaction: discord.Interaction,
    channel: discord.abc.GuildChannel,
):
    # Accept any guild channel, then validate it supports sending messages.
    # This is more tolerant than narrow type-hinting: avoids Discord rejecting
    # the interaction for category/thread/forum channels while we can give
    # the user a readable error instead.
    if not isinstance(channel, (discord.TextChannel, discord.VoiceChannel)):
        name = getattr(channel, "name", "channel")
        await interaction.response.send_message(
            f"⚠️ `#{name}` isn't a regular text channel — pick a plain `#` channel.",
            ephemeral=True,
        )
        return
    update_setting(interaction.guild.id, "verify_channel_id", channel.id)
    await interaction.response.send_message(
        f"✅ Verify channel set to {channel.mention}.", ephemeral=True
    )
    await admin_log(interaction, "set-verify-channel", f"set to {channel.mention}")


@bot.tree.command(name="set-log-channel", description="Set the channel for verification event logs. Omit to disable logging.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(channel="Any text channel the bot can post in. Leave empty to disable.")
async def set_log_channel(
    interaction: discord.Interaction,
    channel: discord.abc.GuildChannel | None = None,
):
    if channel is not None and not isinstance(
        channel, (discord.TextChannel, discord.VoiceChannel)
    ):
        await interaction.response.send_message(
            f"⚠️ `#{channel.name}` isn't a regular text channel — "
            "pick a plain `#` channel.",
            ephemeral=True,
        )
        return
    value = channel.id if channel else None
    print(
        f"[set-log-channel] guild={interaction.guild.id} "
        f"channel_arg={channel!r} value_to_save={value}",
        flush=True,
    )
    update_setting(interaction.guild.id, "log_channel_id", value)
    verify = get_settings(interaction.guild.id).get("log_channel_id")
    print(
        f"[set-log-channel] guild={interaction.guild.id} "
        f"read-back value={verify} (should match {value})",
        flush=True,
    )

    msg = f"✅ Log channel set to {channel.mention}." if channel else "✅ Logging disabled."
    await interaction.response.send_message(msg, ephemeral=True)
    detail = f"set to {channel.mention}" if channel else "logging disabled"
    await admin_log(interaction, "set-log-channel", detail)


@bot.tree.command(name="set-captcha-length", description="How many characters the CAPTCHA has (5-8).")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(length="5 = easy, 6 = normal, 7-8 = hard")
async def set_captcha_length(interaction: discord.Interaction, length: app_commands.Range[int, 5, 8]):
    update_setting(interaction.guild.id, "captcha_length", length)
    await interaction.response.send_message(
        f"✅ CAPTCHA length set to {length}.", ephemeral=True
    )
    await admin_log(interaction, "set-captcha-length", f"set to {length}")


@bot.tree.command(name="set-cooldown", description="Seconds between CAPTCHA requests per user.")
@app_commands.default_permissions(administrator=True)
async def set_cooldown(interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 600]):
    update_setting(interaction.guild.id, "cooldown_seconds", seconds)
    await interaction.response.send_message(
        f"✅ Cooldown set to {seconds} seconds.", ephemeral=True
    )
    await admin_log(interaction, "set-cooldown", f"set to {seconds}s")


@bot.tree.command(name="set-max-attempts", description="Wrong answers before auto-kick. 0 disables kicking.")
@app_commands.default_permissions(administrator=True)
async def set_max_attempts(interaction: discord.Interaction, attempts: app_commands.Range[int, 0, 20]):
    update_setting(interaction.guild.id, "max_attempts", attempts)
    label = "disabled" if attempts == 0 else f"{attempts}"
    await interaction.response.send_message(
        f"✅ Max attempts set to {label}.", ephemeral=True
    )
    await admin_log(interaction, "set-max-attempts", f"set to {label}")


@bot.tree.command(name="set-modal-timeout", description="Seconds before the 'Enter Answer' button expires.")
@app_commands.default_permissions(administrator=True)
async def set_modal_timeout(interaction: discord.Interaction, seconds: app_commands.Range[int, 30, 1800]):
    update_setting(interaction.guild.id, "modal_timeout", seconds)
    await interaction.response.send_message(
        f"✅ Modal timeout set to {seconds} seconds.", ephemeral=True
    )
    await admin_log(interaction, "set-modal-timeout", f"set to {seconds}s")


@bot.tree.command(name="patreon-add", description="Add a role whose holders skip the CAPTCHA (e.g. a Patreon tier).")
@app_commands.default_permissions(administrator=True)
async def patreon_add(interaction: discord.Interaction, role: discord.Role):
    s = get_settings(interaction.guild.id)
    ids = s["patreon_role_ids"]
    if role.id in ids:
        await interaction.response.send_message(
            f"{role.mention} is already in the Patreon list.", ephemeral=True
        )
        return
    ids.append(role.id)
    update_setting(interaction.guild.id, "patreon_role_ids", ids)
    await interaction.response.send_message(
        f"✅ {role.mention} added to Patreon auto-verify list.", ephemeral=True
    )
    await admin_log(interaction, "patreon-add", f"added {role.mention}")


@bot.tree.command(name="patreon-remove", description="Remove a role from the Patreon auto-verify list.")
@app_commands.default_permissions(administrator=True)
async def patreon_remove(interaction: discord.Interaction, role: discord.Role):
    s = get_settings(interaction.guild.id)
    ids = s["patreon_role_ids"]
    if role.id not in ids:
        await interaction.response.send_message(
            f"{role.mention} isn't in the Patreon list.", ephemeral=True
        )
        return
    ids.remove(role.id)
    update_setting(interaction.guild.id, "patreon_role_ids", ids)
    await interaction.response.send_message(
        f"✅ {role.mention} removed from Patreon auto-verify list.", ephemeral=True
    )
    await admin_log(interaction, "patreon-remove", f"removed {role.mention}")


# =============================================================================
# /lockdown and /lockdown-undo — auto-configure channel permissions so that
# unverified members can only see the verify channel.
# =============================================================================
#
# Logic:
# - For every channel that's currently public (i.e. @everyone has no `view`
#   deny overwrite), we deny @everyone's view permission and explicitly
#   allow the Verified role and any configured Patreon roles. Other roles'
#   existing channel overwrites are left untouched. Channels that are
#   ALREADY private to @everyone (mod-only, etc.) are skipped — we don't
#   want to grant Verified members access to mod channels.
# - The verify channel itself gets the inverse: @everyone allowed to view,
#   Verified + Patreon roles denied (so they don't see it cluttering their
#   list once they've got past it).
# - We never touch role.permissions at the server level. Everything is
#   per-channel overwrites, which means Administrators (who bypass
#   overwrites) keep working unchanged.
#
# The flow uses a confirmation View so admins always see a preview first.

LOCKDOWN_CONFIRM_TIMEOUT_SECONDS = 60


def _compute_lockdown_plan(guild: discord.Guild, settings: dict) -> dict:
    """Inspect every channel and split into 'will lock', 'will skip', and
    'can't touch'. Returns a dict the preview embed and the apply step
    both consume.

    A channel goes into `unmanageable` when the bot's effective permissions
    on it lack Manage Roles — usually because a category overwrite blocks
    the bot's role even though it has Manage Roles server-wide. We flag
    these in the preview (grouped by category, since fixing the category
    fixes all its children at once) and skip them in the apply step
    instead of hitting Forbidden mid-run.
    """
    verified_role_id = settings.get("verified_role_id")
    verify_channel_id = settings.get("verify_channel_id")
    patreon_role_ids = settings.get("patreon_role_ids", []) or []
    me = guild.me

    to_lock: list[discord.abc.GuildChannel] = []
    to_skip_already_private: list[discord.abc.GuildChannel] = []
    unmanageable: list[discord.abc.GuildChannel] = []

    for ch in guild.channels:
        # Categories aren't directly modified — channel-level overwrites
        # are what determine actual user visibility.
        if isinstance(ch, discord.CategoryChannel):
            continue
        # The verify channel is handled separately (different rules).
        if ch.id == verify_channel_id:
            continue
        # Pre-flight FIRST: does the bot have View Channel + Manage
        # Channels + Manage Permissions here? (The API calls the last one
        # `manage_roles` but Discord's UI labels it "Manage Permissions"
        # — same permission.) View Channel is foundational; without it,
        # Discord treats other perms as dead. We check this BEFORE the
        # "already private" classification below, so channels with
        # leftover @everyone-deny from a previously-failed lockdown still
        # surface in the "Can't manage" section instead of being silently
        # filed under "skipping already-private channels".
        eff = ch.permissions_for(me)
        if not (eff.view_channel and eff.manage_channels and eff.manage_roles):
            unmanageable.append(ch)
            continue
        # Treat already-private channels (e.g. mod-only) as off-limits to
        # avoid accidentally granting Verified/Patreon access there.
        ow = ch.overwrites_for(guild.default_role)
        if ow.view_channel is False:
            to_skip_already_private.append(ch)
            continue
        to_lock.append(ch)

    # Check the verify channel separately. If we can't manage it AND it's
    # not already public to @everyone, lockdown will leave members locked
    # out of verification — surface this loudly in the preview.
    verify_channel = guild.get_channel(verify_channel_id) if verify_channel_id else None
    verify_unmanageable = False
    if verify_channel is not None:
        veff = verify_channel.permissions_for(me)
        verify_unmanageable = not (
            veff.view_channel and veff.manage_channels and veff.manage_roles
        )

    return {
        "to_lock": to_lock,
        "to_skip": to_skip_already_private,
        "unmanageable": unmanageable,
        "verify_channel": verify_channel,
        "verify_unmanageable": verify_unmanageable,
        "verified_role_id": verified_role_id,
        "patreon_role_ids": list(patreon_role_ids),
    }


def _group_channels_by_category(channels: list) -> dict[str, list[str]]:
    """Group channel name strings by their parent category name.
    Channels without a category land in 'Uncategorized'. Used by the
    lockdown preview to give the admin a category-level fix-list."""
    groups: dict[str, list[str]] = {}
    for ch in channels:
        cat_name = ch.category.name if ch.category else "Uncategorized"
        groups.setdefault(cat_name, []).append(f"#{ch.name}")
    return groups


def _build_lockdown_preview(guild: discord.Guild, plan: dict) -> discord.Embed:
    """Embed shown to the admin before they confirm."""
    verify_channel = plan["verify_channel"]
    embed = discord.Embed(
        title="🔒 Lockdown preview",
        description=(
            f"This will modify **{len(plan['to_lock'])}** channel"
            f"{'' if len(plan['to_lock']) == 1 else 's'} so unverified members can "
            f"only see {verify_channel.mention if verify_channel else '#verify'}."
        ),
        color=discord.Color.orange(),
    )

    verified_role = guild.get_role(plan["verified_role_id"])
    patreon_roles = [
        guild.get_role(rid) for rid in plan["patreon_role_ids"]
    ]
    patreon_roles = [r for r in patreon_roles if r is not None]

    keep_lines = []
    if verified_role:
        keep_lines.append(f"**Verified role:** {verified_role.mention}")
    if patreon_roles:
        keep_lines.append(
            "**Patreon roles:** " + ", ".join(r.mention for r in patreon_roles)
        )
    else:
        keep_lines.append("**Patreon roles:** _(none configured)_")
    keep_lines.append("**Other role overwrites:** left untouched")
    keep_lines.append("**Administrators:** unaffected (bypass overwrites)")

    embed.add_field(
        name="✅ Will keep access",
        value="\n".join(keep_lines),
        inline=False,
    )

    if plan["to_skip"]:
        names = ", ".join(f"#{c.name}" for c in plan["to_skip"][:10])
        if len(plan["to_skip"]) > 10:
            names += f" _(+{len(plan['to_skip']) - 10} more)_"
        embed.add_field(
            name=f"⏭️ Skipping {len(plan['to_skip'])} already-private channel"
                 f"{'' if len(plan['to_skip']) == 1 else 's'}",
            value=names[:1024],
            inline=False,
        )

    # Surface channels we can't touch BEFORE the user confirms — saves
    # them a round trip of "modified 0, couldn't modify 4". Group by
    # category since the actual fix is almost always at the category
    # level (one overwrite there cascades to all its channels).
    unman = plan.get("unmanageable", [])
    verify_unman = plan.get("verify_unmanageable", False)
    if unman or verify_unman:
        parts: list[str] = []

        if verify_unman and plan["verify_channel"] is not None:
            parts.append(
                f"**{plan['verify_channel'].mention}** _(the verify channel — "
                f"if it's not already public to `@everyone`, verification will break)_"
            )
            parts.append("")

        if unman:
            groups = _group_channels_by_category(unman)
            for cat_name, ch_names in groups.items():
                # Truncate per-category if it's huge so we fit in the field
                shown = ", ".join(ch_names[:8])
                if len(ch_names) > 8:
                    shown += f" _(+{len(ch_names) - 8} more)_"
                parts.append(f"**{cat_name}:** {shown}")
            parts.append("")

        parts.append(
            "**Fix:** edit each category above → Permissions → add "
            "GateKeepr's role → grant Manage Roles. Channels inherit from "
            "their category, so one overwrite there fixes all of them. "
            "Then re-run `/lockdown`."
        )

        n_unman = len(unman) + (1 if verify_unman else 0)
        embed.add_field(
            name=f"🔧 Can't manage {n_unman} channel"
                 f"{'' if n_unman == 1 else 's'} — won't be touched",
            value="\n".join(parts)[:1024],
            inline=False,
        )

    embed.add_field(
        name="⚠️ Heads up",
        value=(
            "Members whose access depends only on server-level role permissions "
            "(without explicit channel allow overwrites) will lose access to "
            "locked channels. If your mod or staff roles already have explicit "
            "channel overwrites, they'll keep them. Run `/lockdown-undo` to "
            "reverse if anything looks wrong."
        ),
        inline=False,
    )

    embed.set_footer(
        text=f"Click Confirm within {LOCKDOWN_CONFIRM_TIMEOUT_SECONDS}s to apply."
    )
    return embed


async def _apply_lockdown(interaction: discord.Interaction, plan: dict):
    """Walk the plan and apply overwrites with a partial-failure-safe order.

    Crucial ordering rule for non-verify channels:
        1. Set ALLOW overwrites for Verified + Patreon roles.
        2. Only after those succeed, deny @everyone.
    If step 1 fails (e.g. one of those roles sits above the bot's role and
    can't be modified), we roll back the allows and abort. The channel is
    left fully untouched — much better than half-locked, where @everyone
    is denied but Verified hasn't been allowed yet (which is what made
    everything invisible in older versions).

    For the verify channel the order inverts: @everyone ALLOW is the only
    critical step, so it goes first. The Verified/Patreon DENY overwrites
    are cosmetic (they hide #verify from people who've already verified)
    and are best-effort — failure there doesn't break verification.
    """
    guild = interaction.guild
    verified_role = guild.get_role(plan["verified_role_id"])
    patreon_roles = [
        guild.get_role(rid) for rid in plan["patreon_role_ids"]
    ]
    patreon_roles = [r for r in patreon_roles if r is not None]
    verify_channel = plan["verify_channel"]

    success = 0
    failed: list[str] = []
    total = len(plan["to_lock"])
    reason = f"Lockdown applied by {interaction.user}"

    # ---- Verify channel: @everyone allow first, role denies are extras --
    if verify_channel is not None:
        ow_perms = verify_channel.permissions_for(guild.me)
        if not (ow_perms.view_channel and ow_perms.manage_channels and ow_perms.manage_roles):
            failed.append(
                f"#{verify_channel.name} (bot can't manage permissions on "
                f"this channel — check role overwrites)"
            )
        else:
            try:
                # Critical step: ensure unverified members can see #verify
                await verify_channel.set_permissions(
                    guild.default_role,
                    view_channel=True,
                    read_message_history=True,
                    reason=reason,
                )
                touched_roles: list[int] = []
                # Cosmetic: hide #verify from already-verified members.
                # If these fail it doesn't break verification, so don't
                # abort the whole channel.
                if verified_role:
                    try:
                        await verify_channel.set_permissions(
                            verified_role, view_channel=False, reason=reason
                        )
                        touched_roles.append(verified_role.id)
                    except discord.HTTPException:
                        pass
                for prole in patreon_roles:
                    try:
                        await verify_channel.set_permissions(
                            prole, view_channel=False, reason=reason
                        )
                        touched_roles.append(prole.id)
                    except discord.HTTPException:
                        pass
                # Log it for /lockdown-undo
                try:
                    record_lockdown(
                        guild.id, verify_channel.id,
                        locked_by_user_id=interaction.user.id,
                        modified_role_ids=touched_roles,
                        is_verify_channel=True,
                    )
                except Exception as e:
                    print(f"[lockdown] failed to record verify channel: {e}", flush=True)
            except discord.Forbidden as e:
                detail = (getattr(e, "text", None) or "Forbidden")[:50]
                failed.append(f"#{verify_channel.name}: {detail}")
            except discord.HTTPException as e:
                failed.append(f"#{verify_channel.name} ({type(e).__name__})")

    # ---- All other public channels: allows first, deny LAST ------------
    for i, channel in enumerate(plan["to_lock"]):
        ow_perms = channel.permissions_for(guild.me)
        if not (ow_perms.view_channel and ow_perms.manage_channels and ow_perms.manage_roles):
            failed.append(
                f"#{channel.name} (bot can't manage permissions here)"
            )
            if i % 5 == 0 or i == total - 1:
                try:
                    progress = discord.Embed(
                        title="🔒 Lockdown in progress…",
                        description=f"Modified **{success}/{total}** channels.",
                        color=discord.Color.orange(),
                    )
                    await interaction.edit_original_response(embed=progress, view=None)
                except discord.HTTPException:
                    pass
            continue

        is_voice = isinstance(channel, (discord.VoiceChannel, discord.StageChannel))
        allow_kwargs = {"view_channel": True}
        if is_voice:
            allow_kwargs["connect"] = True
            allow_kwargs["speak"] = True
        else:
            allow_kwargs["send_messages"] = True
            allow_kwargs["read_message_history"] = True

        async def _rollback(roles_to_clear):
            """Best-effort: undo any allows we managed to apply on this
            channel before the failure. Channel ends up fully untouched."""
            for r in roles_to_clear:
                try:
                    await channel.set_permissions(r, overwrite=None)
                except discord.HTTPException:
                    pass

        # Phase 1: allows (Verified + Patreon)
        applied_roles: list[discord.Role] = []
        phase1_failed_msg: str | None = None
        try:
            if verified_role:
                await channel.set_permissions(
                    verified_role, reason=reason, **allow_kwargs
                )
                applied_roles.append(verified_role)
            for prole in patreon_roles:
                await channel.set_permissions(
                    prole, reason=reason, **allow_kwargs
                )
                applied_roles.append(prole)
        except discord.Forbidden as e:
            detail = (getattr(e, "text", None) or "Forbidden")[:50]
            phase1_failed_msg = f"#{channel.name}: couldn't grant Verified/Patreon — {detail}"
        except discord.HTTPException as e:
            phase1_failed_msg = f"#{channel.name} ({type(e).__name__} during allow)"

        if phase1_failed_msg is not None:
            await _rollback(applied_roles)
            failed.append(phase1_failed_msg)
        else:
            # Phase 2: deny @everyone — this is what actually locks it down
            try:
                await channel.set_permissions(
                    guild.default_role, view_channel=False, reason=reason
                )
                try:
                    record_lockdown(
                        guild.id, channel.id,
                        locked_by_user_id=interaction.user.id,
                        modified_role_ids=[r.id for r in applied_roles],
                        is_verify_channel=False,
                    )
                except Exception as e:
                    print(f"[lockdown] failed to record {channel.id}: {e}", flush=True)
                success += 1
            except discord.Forbidden as e:
                detail = (getattr(e, "text", None) or "Forbidden")[:50]
                failed.append(f"#{channel.name}: couldn't deny @everyone — {detail}")
                await _rollback(applied_roles)
            except discord.HTTPException as e:
                failed.append(f"#{channel.name} ({type(e).__name__} during deny)")
                await _rollback(applied_roles)

        if i % 5 == 0 or i == total - 1:
            try:
                progress = discord.Embed(
                    title="🔒 Lockdown in progress…",
                    description=f"Modified **{success}/{total}** channels.",
                    color=discord.Color.orange(),
                )
                await interaction.edit_original_response(embed=progress, view=None)
            except discord.HTTPException:
                pass

    # ---- Final report --------------------------------------------------
    final = discord.Embed(
        title="✅ Lockdown complete",
        description=(
            f"Modified **{success}** channel{'' if success == 1 else 's'}.\n"
            f"{verify_channel.mention if verify_channel else '#verify'} is now "
            f"the only channel unverified members can see."
        ),
        color=discord.Color.green(),
    )
    if failed:
        names = "\n".join(f"• {f}" for f in failed[:15])
        if len(failed) > 15:
            names += f"\n…(+{len(failed) - 15} more)"
        final.add_field(
            name=f"⚠️ Couldn't modify {len(failed)} channel"
                 f"{'' if len(failed) == 1 else 's'}",
            value=names[:1024],
            inline=False,
        )
        final.set_footer(
            text="Specific reason shown next to each channel name above."
        )
    final.add_field(
        name="Reverse",
        value="Run `/lockdown-undo` to remove the @everyone deny we added.",
        inline=False,
    )

    try:
        await interaction.edit_original_response(embed=final, view=None)
    except discord.HTTPException:
        pass

    await log_event(
        guild,
        f"🔒 **Lockdown applied** by {interaction.user.mention}: "
        f"{success}/{total} channels locked, {len(failed)} failed.",
        color=discord.Color.orange(),
    )


class LockdownConfirmView(discord.ui.View):
    """Two-button confirmation. Locked to the user who invoked the command."""

    def __init__(self, plan: dict, invoker_id: int):
        super().__init__(timeout=LOCKDOWN_CONFIRM_TIMEOUT_SECONDS)
        self.plan = plan
        self.invoker_id = invoker_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.invoker_id:
            await interaction.response.send_message(
                "Only the admin who ran the command can confirm.", ephemeral=True
            )
            return False
        return True

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True

    @discord.ui.button(label="Confirm lockdown", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Disable the buttons so they can't be re-clicked while we work
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)
        await _apply_lockdown(interaction, self.plan)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        cancelled = discord.Embed(
            title="Cancelled",
            description="No channels were modified.",
            color=discord.Color.greyple(),
        )
        await interaction.response.edit_message(embed=cancelled, view=self)


@bot.tree.command(
    name="lockdown",
    description="Lock all public channels except #verify behind verification.",
)
@app_commands.default_permissions(manage_guild=True)
async def lockdown_command(interaction: discord.Interaction):
    settings = get_settings(interaction.guild.id)

    verified_role_id = settings.get("verified_role_id")
    verify_channel_id = settings.get("verify_channel_id")
    if not verified_role_id or not verify_channel_id:
        await interaction.response.send_message(
            "❌ Set both `/set-verified-role` and `/set-verify-channel` "
            "(or use the dashboard) before running lockdown.",
            ephemeral=True,
        )
        return

    verified_role = interaction.guild.get_role(verified_role_id)
    verify_channel = interaction.guild.get_channel(verify_channel_id)
    if not verified_role:
        await interaction.response.send_message(
            "❌ Configured verified role no longer exists. "
            "Re-set it with `/set-verified-role`.",
            ephemeral=True,
        )
        return
    if not verify_channel:
        await interaction.response.send_message(
            "❌ Configured verify channel no longer exists. "
            "Re-set it with `/set-verify-channel`.",
            ephemeral=True,
        )
        return

    if not interaction.guild.me.guild_permissions.administrator:
        await interaction.response.send_message(
            "❌ Lockdown requires the bot to have **Administrator** on this "
            "server. Granular per-channel permissions get blocked by category "
            "overwrites in too many setups, so this command is gated on admin "
            "to keep behavior predictable.\n\n"
            "**Fix:** Server Settings → Roles → GateKeepr → enable "
            "**Administrator**. Re-run when ready. You can revoke admin "
            "after the lockdown is in place if you prefer.",
            ephemeral=True,
        )
        return

    # Bot's top role must outrank the verified role to modify its overwrites.
    # Administrator does NOT bypass role hierarchy — Discord still won't let
    # us modify the overwrite of a role positioned above ours.
    if interaction.guild.me.top_role <= verified_role:
        await interaction.response.send_message(
            "❌ My role needs to be **above** the verified role in your "
            "server's role list. Move it up and try again.",
            ephemeral=True,
        )
        return

    plan = _compute_lockdown_plan(interaction.guild, settings)
    if not plan["to_lock"] and not plan["verify_channel"]:
        await interaction.response.send_message(
            "Nothing to lock down — every channel is either already private "
            "or matches the desired state.",
            ephemeral=True,
        )
        return

    embed = _build_lockdown_preview(interaction.guild, plan)
    view = LockdownConfirmView(plan, interaction.user.id)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


# ---------------------------------------------------------------------------
# /lockdown-undo — strip the @everyone view-deny we added.
# Only undoes channels that look like we locked them (i.e. @everyone has an
# explicit view-deny). Other private channels (mod-only) are left alone.
# ---------------------------------------------------------------------------

class LockdownUndoConfirmView(discord.ui.View):
    def __init__(self, records: list, ghost_ids: list[int], invoker_id: int):
        super().__init__(timeout=LOCKDOWN_CONFIRM_TIMEOUT_SECONDS)
        # records: list of {"channel": GuildChannel, "modified_role_ids": list[int],
        #                   "is_verify_channel": bool}
        self.records = records
        self.ghost_ids = ghost_ids
        self.invoker_id = invoker_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.invoker_id:
            await interaction.response.send_message(
                "Only the admin who ran the command can confirm.", ephemeral=True
            )
            return False
        return True

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True

    @discord.ui.button(label="Confirm undo", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)

        guild = interaction.guild
        success = 0
        failed: list[str] = []
        unlocked_ids: list[int] = []
        reason = f"Lockdown undo by {interaction.user}"

        for rec in self.records:
            ch = rec["channel"]
            ow_perms = ch.permissions_for(guild.me)
            if not (ow_perms.view_channel and ow_perms.manage_channels and ow_perms.manage_roles):
                failed.append(
                    f"#{ch.name} (bot can't manage permissions here)"
                )
                continue

            channel_failed = False
            try:
                # Remove the @everyone overwrite — restores inheritance
                # (which is what the channel had before lockdown).
                await ch.set_permissions(
                    guild.default_role, overwrite=None, reason=reason
                )
            except discord.Forbidden as e:
                detail = (getattr(e, "text", None) or "Forbidden")[:50]
                failed.append(f"#{ch.name}: {detail}")
                channel_failed = True
            except discord.HTTPException as e:
                failed.append(f"#{ch.name} ({type(e).__name__})")
                channel_failed = True

            # Remove the role overwrites we recorded too. Best-effort —
            # if any of these fail it's noise, not a reason to mark the
            # channel itself as failed (the @everyone removal is what
            # actually un-locks it).
            for role_id in rec["modified_role_ids"]:
                role = guild.get_role(role_id)
                if role is None:
                    continue
                try:
                    await ch.set_permissions(role, overwrite=None, reason=reason)
                except discord.HTTPException:
                    pass

            if not channel_failed:
                success += 1
                unlocked_ids.append(ch.id)

        try:
            clear_lockdown_history(guild.id, unlocked_ids + self.ghost_ids)
        except Exception as e:
            print(f"[lockdown-undo] failed to clear history: {e}", flush=True)

        embed = discord.Embed(
            title="✅ Lockdown undone",
            description=(
                f"Reopened **{success}** channel"
                f"{'' if success == 1 else 's'} — removed every overwrite "
                f"GateKeepr added (the @everyone deny plus any Verified/"
                f"Patreon overwrites)."
            ),
            color=discord.Color.green(),
        )
        if self.ghost_ids:
            embed.description += (
                f"\nCleared {len(self.ghost_ids)} stale entr"
                f"{'y' if len(self.ghost_ids) == 1 else 'ies'} for deleted channels."
            )
        if failed:
            names = "\n".join(f"• {f}" for f in failed[:15])
            if len(failed) > 15:
                names += f"\n…(+{len(failed) - 15} more)"
            embed.add_field(
                name=f"⚠️ Couldn't reopen {len(failed)} channel"
                     f"{'' if len(failed) == 1 else 's'}",
                value=names[:1024],
                inline=False,
            )
            embed.set_footer(
                text="Failed channels stay in lockdown history — fix perms and re-run."
            )
        await interaction.edit_original_response(embed=embed, view=None)

        await log_event(
            guild,
            f"🔓 **Lockdown undone** by {interaction.user.mention}: "
            f"{success} channels reopened, {len(failed)} failed.",
            color=discord.Color.blurple(),
        )

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        cancelled = discord.Embed(
            title="Cancelled",
            description="No channels were modified.",
            color=discord.Color.greyple(),
        )
        await interaction.response.edit_message(embed=cancelled, view=self)


@bot.tree.command(
    name="lockdown-undo",
    description="Reverse a lockdown: remove every overwrite GateKeepr added.",
)
@app_commands.default_permissions(manage_guild=True)
async def lockdown_undo_command(interaction: discord.Interaction):
    if not interaction.guild.me.guild_permissions.administrator:
        await interaction.response.send_message(
            "❌ Undo requires the bot to have **Administrator** on this "
            "server (same gate as `/lockdown`). Re-grant Administrator to "
            "GateKeepr in Server Settings → Roles, run undo, then revoke "
            "if you want.",
            ephemeral=True,
        )
        return

    # Source of truth: the lockdown_history table written by /lockdown.
    # No more guessing-by-signature — the bot knows exactly which channels
    # it modified AND which role overwrites it set on each one.
    raw_records = get_lockdown_records(interaction.guild.id)

    if not raw_records:
        await interaction.response.send_message(
            "Nothing to undo — GateKeepr hasn't locked any channels in this server.",
            ephemeral=True,
        )
        return

    # Resolve channel IDs to objects. Some may have been deleted since
    # lockdown — those are 'ghosts' that we'll just clean from history
    # without trying to modify them.
    records: list[dict] = []
    ghost_ids: list[int] = []
    for r in raw_records:
        ch = interaction.guild.get_channel(r["channel_id"])
        if ch is None:
            ghost_ids.append(r["channel_id"])
        else:
            records.append({
                "channel": ch,
                "modified_role_ids": r["modified_role_ids"],
                "is_verify_channel": r["is_verify_channel"],
            })

    if not records:
        clear_lockdown_history(interaction.guild.id, ghost_ids)
        await interaction.response.send_message(
            f"Nothing to undo — all {len(ghost_ids)} previously locked channel(s) "
            f"have been deleted. Cleared the lockdown history.",
            ephemeral=True,
        )
        return

    embed = discord.Embed(
        title="🔓 Undo preview",
        description=(
            f"This will remove every overwrite GateKeepr added to **{len(records)}** "
            f"channel{'' if len(records) == 1 else 's'} — the @everyone "
            f"deny plus any Verified/Patreon overwrites we set on each one."
        ),
        color=discord.Color.blurple(),
    )
    sample = ", ".join(f"#{r['channel'].name}" for r in records[:15])
    if len(records) > 15:
        sample += f" _(+{len(records) - 15} more)_"
    embed.add_field(name="Channels to reopen", value=sample[:1024], inline=False)

    if ghost_ids:
        embed.add_field(
            name=f"🗑️ {len(ghost_ids)} deleted channel"
                 f"{'' if len(ghost_ids) == 1 else 's'}",
            value="These no longer exist; their history entries will be cleared.",
            inline=False,
        )

    embed.set_footer(
        text=f"Click Confirm within {LOCKDOWN_CONFIRM_TIMEOUT_SECONDS}s to proceed."
    )

    view = LockdownUndoConfirmView(records, ghost_ids, interaction.user.id)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@bot.tree.command(name="reset-settings", description="Reset all verification settings to defaults.")
@app_commands.default_permissions(administrator=True)
async def reset_settings_command(interaction: discord.Interaction):
    # Log BEFORE resetting -- after reset, the log channel ID is gone and
    # we couldn't post the "reset happened" message anywhere.
    await admin_log(interaction, "reset-settings", "all settings wiped to defaults")
    reset_settings(interaction.guild.id)
    await interaction.response.send_message(
        "✅ Settings reset to defaults. Reconfigure with the `/set-*` commands.\n"
        "*(Your admin logs toggle was preserved.)*",
        ephemeral=True,
    )


@bot.tree.command(name="set-admin-logs", description="Enable or disable logging of admin command use.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(enabled="True to log every admin command, False to disable.")
async def set_admin_logs(interaction: discord.Interaction, enabled: bool):
    """Toggles the per-guild admin_logs_enabled flag.

    When enabled (default), every admin slash command posts a log entry to
    the configured log channel showing who used which command. Turn off if
    you find the logs noisy or if your admins want privacy from each other.
    """
    update_setting(interaction.guild.id, "admin_logs_enabled", 1 if enabled else 0)
    status = "enabled" if enabled else "disabled"
    await interaction.response.send_message(
        f"✅ Admin command logging is now **{status}**.", ephemeral=True
    )
    # Log the toggle itself. If we just turned it ON, this will post.
    # If we turned it OFF, admin_log will silently skip -- which is the
    # expected behavior (no more admin logs from this point).
    await admin_log(interaction, "set-admin-logs", f"turned {status}")


# =============================================================================
# SLASH COMMAND -- /help
# =============================================================================

@bot.tree.command(name="help", description="Show all available commands and what they do.")
@app_commands.default_permissions(administrator=True)
async def help_command(interaction: discord.Interaction):
    """Displays every slash command grouped by category. Admin-only, ephemeral.

    Edit the descriptions below if you want to reword anything for your
    end-users.
    """
    embed = discord.Embed(
        title="🤖 Verification Bot — Commands",
        description=(
            "Here's everything I can do. All commands require "
            "**Administrator** permission.\n"
            "Responses are ephemeral (only you see them)."
        ),
        color=discord.Color.blurple(),
    )

    # --- General commands ---
    embed.add_field(
        name="General",
        value=(
            "`/help` — Show this message."
        ),
        inline=False,
    )

    # --- Verification setup commands ---
    embed.add_field(
        name="Verification Setup",
        value=(
            "`/setup-verify` — Post the permanent Verify button in your configured "
            "verify channel.\n"
            "`/grandfather` — Grant the Verified role to every existing non-bot "
            "member. Run this once **before** locking down channel permissions "
            "so your existing community isn't locked out.\n"
            "`/lockdown` — Auto-lock all public channels behind the Verified role "
            "(plus any Patreon roles). Shows a preview before applying.\n"
            "`/lockdown-undo` — Reverse a lockdown by removing the @everyone "
            "view-deny GateKeepr added."
        ),
        inline=False,
    )

    # --- View and reset ---
    embed.add_field(
        name="View, Reset & Export",
        value=(
            "`/settings` — Show this server's current settings.\n"
            "`/stats` — Show verification activity stats.\n"
            "`/reset-settings` — Wipe settings to defaults.\n"
            "`/clear-invite-data confirm:True` — Wipe tracking history. Keeps settings.\n"
            "`/export-data` — Download all bot data as JSON."
        ),
        inline=False,
    )

    # --- Required settings ---
    embed.add_field(
        name="Required Settings",
        value=(
            "`/set-verified-role <role>` — The role granted on successful "
            "verification. **Required.**\n"
            "`/set-verify-channel <channel>` — Where the Verify button "
            "lives. **Required.**"
        ),
        inline=False,
    )

    # --- Optional settings ---
    embed.add_field(
        name="Optional Settings",
        value=(
            "`/set-log-channel [channel]` — Where verification events are "
            "logged. Omit the channel to disable logging.\n"
            "`/set-admin-logs <true|false>` — Whether admin command use is "
            "logged to the log channel. Default on.\n"
            "`/set-captcha-length <5-8>` — How many characters the CAPTCHA "
            "image has. Default `6`.\n"
            "`/set-cooldown <seconds>` — Wait time between CAPTCHA requests "
            "per user. Default `30`.\n"
            "`/set-max-attempts <0-20>` — Wrong answers before auto-kick. "
            "`0` disables kicking. Default `3`.\n"
            "`/set-modal-timeout <30-1800>` — Seconds before the Enter "
            "Answer button expires. Default `300`."
        ),
        inline=False,
    )

    # --- Invite Tracking ---
    embed.add_field(
        name="Invite Tracking",
        value=(
            "`/invite-stats` — Dashboard of joins, bans, top inviters.\n"
            "`/invite-audit code:<code>` — Who joined via a specific invite.\n"
            "`/inviter-score user:<user>` — Their invite reputation.\n"
            "`/set-invite-autodisable threshold:<n>` — Auto-disable at N bans. Default `5`, `0` off.\n"
            "`/set-inviter-notifications <true|false>` — DM inviters on bans. Default off.\n"
            "`/set-retention months:<n>` — Prune join records older than N months. Default `12`."
        ),
        inline=False,
    )

    # --- Patreon auto-verify ---
    embed.add_field(
        name="Patreon Auto-Verify",
        value=(
            "`/patreon-add <role>` — Add a role whose holders skip the "
            "CAPTCHA (e.g. your Patreon tier roles).\n"
            "`/patreon-remove <role>` — Remove a role from the "
            "auto-verify list."
        ),
        inline=False,
    )

    # --- Footer: quick start order ---
    embed.add_field(
        name="🚀 First-time setup order",
        value=(
            "1. `/set-verified-role`\n"
            "2. `/set-verify-channel`\n"
            "3. `/set-log-channel` *(optional)*\n"
            "4. `/setup-verify` — posts the button in your verify channel\n"
            "5. `/grandfather` — before locking channel permissions\n"
            "6. Lock `@everyone` out of non-verify channels in Server Settings"
        ),
        inline=False,
    )

    await interaction.response.send_message(embed=embed, ephemeral=True)


# =============================================================================
# SLASH COMMANDS -- INVITE TRACKING & DATA MANAGEMENT
# =============================================================================

@bot.tree.command(name="invite-stats", description="Summary of invite tracking for this server.")
@app_commands.default_permissions(administrator=True)
async def invite_stats_command(interaction: discord.Interaction):
    await admin_log(interaction, "invite-stats", "viewed invite dashboard")
    s = invite_stats_summary(interaction.guild.id)
    embed = discord.Embed(title="📊 Invite Tracking — Summary", color=discord.Color.purple())
    embed.add_field(name="Total joins logged", value=str(s["total_joins"]), inline=True)
    embed.add_field(name="Joins with invite attributed", value=str(s["tracked_joins"]), inline=True)
    embed.add_field(name="Total bans logged", value=str(s["total_bans"]), inline=True)
    embed.add_field(name="Auto-disabled invites", value=str(s["disabled_count"]), inline=True)
    if s["top_inviters"]:
        lines = [f"**{r['inviter_name'] or 'Unknown'}** — {r['c']} invites" for r in s["top_inviters"]]
        embed.add_field(name="Top inviters", value="\n".join(lines), inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="invite-audit", description="Show everyone who joined via a specific invite code.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(code="The invite code (e.g. 'abc123', not the full URL).")
async def invite_audit_command(interaction: discord.Interaction, code: str):
    await admin_log(interaction, "invite-audit", f"audited `{code}`")
    data = audit_invite(interaction.guild.id, code)
    if not data["joins"]:
        await interaction.response.send_message(
            f"No joins recorded for invite `{code}`.", ephemeral=True
        )
        return
    embed = discord.Embed(
        title=f"🔍 Invite Audit — `{code}`",
        color=discord.Color.orange() if data["disabled"] else discord.Color.purple(),
    )
    if data["disabled"]:
        embed.description = (
            f"⚠️ This invite is **auto-disabled** "
            f"(at {data['disabled']['disabled_at']} after "
            f"{data['disabled']['ban_count']} bans)."
        )
    lines = []
    for j in data["joins"][:20]:
        banned = "🔨 " if j["user_id"] in data["banned_ids"] else ""
        lines.append(f"{banned}**{j['username']}** — {j['joined_at']}")
    embed.add_field(
        name=f"Joiners ({len(data['joins'])} total, {len(data['banned_ids'])} banned)",
        value="\n".join(lines) if lines else "None",
        inline=False,
    )
    if len(data["joins"]) > 20:
        embed.set_footer(text=f"Showing 20 of {len(data['joins'])}. Export data for full list.")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="inviter-score", description="Reputation snapshot for a member who's invited others.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(user="The member whose invite record you want to see.")
async def inviter_score_command(interaction: discord.Interaction, user: discord.Member):
    await admin_log(interaction, "inviter-score", f"checked score for {user}")
    s = inviter_stats(interaction.guild.id, user.id)
    total = s["total_invited"]
    banned = s["total_banned"]
    ban_rate = (banned / total * 100) if total else 0
    embed = discord.Embed(
        title=f"📇 Inviter Score — {user}",
        color=discord.Color.red() if ban_rate > 20 else discord.Color.green(),
    )
    embed.add_field(name="Total people invited", value=str(total), inline=True)
    embed.add_field(name="Later banned", value=f"{banned} ({ban_rate:.1f}%)", inline=True)
    if s["top_codes"]:
        lines = [f"`{r['invite_code']}` — {r['uses']} uses" for r in s["top_codes"]]
        embed.add_field(name="Their invite codes", value="\n".join(lines), inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="set-invite-autodisable", description="Auto-disable an invite after N bans from it. 0 to turn off.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(threshold="Number of bans from a single invite before it's auto-disabled. 0 disables this feature.")
async def set_invite_autodisable(
    interaction: discord.Interaction,
    threshold: app_commands.Range[int, 0, 100],
):
    update_setting(interaction.guild.id, "invite_autodisable_threshold", threshold)
    label = "disabled" if threshold == 0 else f"{threshold} bans"
    await interaction.response.send_message(
        f"✅ Invite auto-disable threshold set to **{label}**.", ephemeral=True
    )
    await admin_log(interaction, "set-invite-autodisable", f"set to {label}")


@bot.tree.command(name="set-inviter-notifications", description="Opt-in: DM inviters when their invitees are banned.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(enabled="True to DM inviters when their invitees get banned. Default off.")
async def set_inviter_notifications(interaction: discord.Interaction, enabled: bool):
    update_setting(interaction.guild.id, "inviter_notifications", 1 if enabled else 0)
    status = "enabled" if enabled else "disabled"
    await interaction.response.send_message(
        f"✅ Inviter notifications **{status}**.\n"
        "*(When enabled, inviters receive a DM when someone they invited is banned.)*",
        ephemeral=True,
    )
    await admin_log(interaction, "set-inviter-notifications", f"turned {status}")


@bot.tree.command(name="set-retention", description="How many months to keep invite/join history.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(months="Months to retain join records before auto-pruning. 0 = keep forever.")
async def set_retention(
    interaction: discord.Interaction,
    months: app_commands.Range[int, 0, 120],
):
    update_setting(interaction.guild.id, "retention_months", months)
    label = "forever" if months == 0 else f"{months} months"
    await interaction.response.send_message(
        f"✅ Join record retention set to **{label}**.\n"
        "*(Ban records are always kept permanently.)*",
        ephemeral=True,
    )
    await admin_log(interaction, "set-retention", f"set to {label}")


@bot.tree.command(name="clear-invite-data", description="Wipe this server's invite/join/ban history. Settings preserved.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(confirm="Must be True to actually run. Prevents accidental wipes.")
async def clear_invite_data(interaction: discord.Interaction, confirm: bool):
    if not confirm:
        await interaction.response.send_message(
            "❌ Pass `confirm: True` to actually wipe the data. Nothing changed.",
            ephemeral=True,
        )
        return
    await admin_log(interaction, "clear-invite-data", "wiping all tracking data")
    counts = clear_tracking_data(interaction.guild.id)
    await refresh_invite_cache(interaction.guild)
    await interaction.response.send_message(
        f"✅ Cleared tracking data:\n"
        f"• {counts['joins']} join records\n"
        f"• {counts['bans']} ban records\n"
        f"• {counts['disabled']} disabled-invite entries\n"
        "*(Settings — verified role, channels, etc. — are untouched.)*",
        ephemeral=True,
    )


@bot.tree.command(name="export-data", description="Download this server's bot data as a JSON file.")
@app_commands.default_permissions(administrator=True)
async def export_data_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    data = export_all_data(interaction.guild.id)
    payload = json.dumps(data, indent=2, default=str).encode("utf-8")
    buf = io.BytesIO(payload)
    filename = f"gatekeepr-{interaction.guild.id}-{datetime.utcnow().strftime('%Y%m%d')}.json"
    file = discord.File(fp=buf, filename=filename)
    await interaction.followup.send(
        content=(
            "📦 Here's every piece of data the bot has on this server. "
            "Includes settings, join history, ban records, and auto-disabled invites."
        ),
        file=file,
        ephemeral=True,
    )
    await admin_log(interaction, "export-data", f"exported {len(payload)} bytes")


# =============================================================================
# RUN
# =============================================================================

if __name__ == "__main__":
    if TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("ERROR: Bot token not set. Either set the DISCORD_BOT_TOKEN "
              "environment variable, or edit the TOKEN line near the top of "
              "this file. See the comments in the code for details.")
        raise SystemExit(1)
    bot.run(TOKEN)
