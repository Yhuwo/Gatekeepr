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
from discord.ext import commands
from captcha.image import ImageCaptcha
import random
import io
import time
import sqlite3
import json
import os
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
DB_PATH = Path(__file__).parent / "bot.db"

# The CAPTCHA character set. Excludes confusing chars like 0/O/1/I/L.
# Applies globally; can't be customized per-server (keeps things simple).
CAPTCHA_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


# =============================================================================
# DATABASE LAYER
# =============================================================================

def db_connect():
    """Open a connection. Called per-operation since SQLite connections
    aren't safe to share across async tasks by default."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    """Create the settings table if it doesn't exist. Safe to call repeatedly.
    Also runs lightweight migrations for columns added in later versions."""
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id           INTEGER PRIMARY KEY,
                verified_role_id   INTEGER,
                verify_channel_id  INTEGER,
                log_channel_id     INTEGER,
                captcha_length     INTEGER NOT NULL DEFAULT 6,
                cooldown_seconds   INTEGER NOT NULL DEFAULT 30,
                max_attempts       INTEGER NOT NULL DEFAULT 3,
                modal_timeout      INTEGER NOT NULL DEFAULT 300,
                patreon_role_ids   TEXT    NOT NULL DEFAULT '[]',
                admin_logs_enabled INTEGER NOT NULL DEFAULT 1
            )
        """)
        # Migration: add admin_logs_enabled column if upgrading from an
        # older schema that didn't have it.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(guild_settings)")}
        if "admin_logs_enabled" not in existing_cols:
            conn.execute(
                "ALTER TABLE guild_settings ADD COLUMN admin_logs_enabled INTEGER NOT NULL DEFAULT 1"
            )
        conn.commit()


def get_settings(guild_id: int) -> dict:
    """Fetch a guild's settings. Creates a default row if none exists."""
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,)
        ).fetchone()
        if row is None:
            # First time we're seeing this guild -- create default row
            conn.execute(
                "INSERT INTO guild_settings (guild_id) VALUES (?)", (guild_id,)
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,)
            ).fetchone()

    settings = dict(row)
    # Parse the JSON-encoded patreon role list
    settings["patreon_role_ids"] = json.loads(settings["patreon_role_ids"] or "[]")
    return settings


def update_setting(guild_id: int, key: str, value):
    """Update a single setting for a guild. Creates the row if needed."""
    get_settings(guild_id)  # ensure row exists

    # Special handling for the JSON-stored list
    if key == "patreon_role_ids":
        value = json.dumps(value)

    with db_connect() as conn:
        conn.execute(
            f"UPDATE guild_settings SET {key} = ? WHERE guild_id = ?",
            (value, guild_id),
        )
        conn.commit()


def reset_settings(guild_id: int):
    """Wipe a guild's settings back to defaults.

    The one exception is `admin_logs_enabled`: if an admin has intentionally
    disabled logging, we don't want a reset to silently re-enable it. We
    preserve the existing value across the wipe.
    """
    with db_connect() as conn:
        row = conn.execute(
            "SELECT admin_logs_enabled FROM guild_settings WHERE guild_id = ?",
            (guild_id,),
        ).fetchone()
        preserved_admin_logs = row["admin_logs_enabled"] if row is not None else 1

        conn.execute("DELETE FROM guild_settings WHERE guild_id = ?", (guild_id,))
        conn.execute(
            "INSERT INTO guild_settings (guild_id, admin_logs_enabled) VALUES (?, ?)",
            (guild_id, preserved_admin_logs),
        )
        conn.commit()


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
        return
    embed = discord.Embed(description=message, color=color, timestamp=datetime.utcnow())
    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        pass


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
            except discord.Forbidden:
                pass
            failed_attempts.pop(key, None)
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

@bot.event
async def on_ready():
    db_init()
    bot.add_view(VerifyView())
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} slash commands.")
    except Exception as e:
        print(f"Failed to sync slash commands: {e}")
    print(f"Logged in as {bot.user} (id: {bot.user.id}) — serving {len(bot.guilds)} guilds")


@bot.event
async def on_guild_join(guild: discord.Guild):
    """A new server invited the bot. Create a default settings row."""
    get_settings(guild.id)
    print(f"Joined new guild: {guild.name} ({guild.id})")


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

    embed = discord.Embed(title="Verification Settings", color=discord.Color.blue())
    embed.add_field(name="Verified role", value=describe_role(s["verified_role_id"]), inline=False)
    embed.add_field(name="Verify channel", value=describe_channel(s["verify_channel_id"]), inline=False)
    embed.add_field(name="Log channel", value=describe_channel(s["log_channel_id"]), inline=False)
    embed.add_field(name="CAPTCHA length", value=s["captcha_length"], inline=True)
    embed.add_field(name="Cooldown (sec)", value=s["cooldown_seconds"], inline=True)
    embed.add_field(name="Max attempts", value=s["max_attempts"] or "Unlimited", inline=True)
    embed.add_field(name="Modal timeout (sec)", value=s["modal_timeout"], inline=True)
    embed.add_field(name="Patreon tier roles", value=patreon_mentions, inline=False)
    embed.add_field(name="Admin logs", value="Enabled" if s.get("admin_logs_enabled") else "Disabled", inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)
    await admin_log(interaction, "settings", "viewed settings")


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
async def set_verify_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    update_setting(interaction.guild.id, "verify_channel_id", channel.id)
    await interaction.response.send_message(
        f"✅ Verify channel set to {channel.mention}.", ephemeral=True
    )
    await admin_log(interaction, "set-verify-channel", f"set to {channel.mention}")


@bot.tree.command(name="set-log-channel", description="Set the channel for verification event logs. Omit to disable logging.")
@app_commands.default_permissions(administrator=True)
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel = None):
    value = channel.id if channel else None
    update_setting(interaction.guild.id, "log_channel_id", value)
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
            "so your existing community isn't locked out."
        ),
        inline=False,
    )

    # --- View and reset ---
    embed.add_field(
        name="View & Reset",
        value=(
            "`/settings` — Show this server's current settings.\n"
            "`/reset-settings` — Wipe this server's settings back to defaults."
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
# RUN
# =============================================================================

if __name__ == "__main__":
    if TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("ERROR: Bot token not set. Either set the DISCORD_BOT_TOKEN "
              "environment variable, or edit the TOKEN line near the top of "
              "this file. See the comments in the code for details.")
        raise SystemExit(1)
    bot.run(TOKEN)
