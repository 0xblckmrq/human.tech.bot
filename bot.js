require("dotenv").config();
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  PermissionsBitField,
  ChannelType,
  SlashCommandBuilder
} = require("discord.js");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const { ethers } = require("ethers");

// ===== CONFIG =====
const TOKEN = process.env.BOT_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const GUILD_ID = process.env.GUILD_ID;
const API_KEY = process.env.WHITELIST_API_KEY;
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL;
const PASSPORT_API_KEY = process.env.PASSPORT_API_KEY;
const ALCHEMY_BASE_KEY = process.env.ALCHEMY_BASE_KEY; // Alchemy Base (NFT API)
const ALCHEMY_ETH_KEY = process.env.ALCHEMY_ETH_KEY;
const ALCHEMY_WEBHOOK_SIGNING_KEY = process.env.ALCHEMY_WEBHOOK_SIGNING_KEY; // Optional: verify Alchemy webhook signatures
const ROLE_REFRESH_MINUTES = Number(process.env.ROLE_REFRESH_MINUTES || 60);
 // Optional: Alchemy Ethereum RPC key to avoid throttled default providers

if (!TOKEN || !CLIENT_ID || !GUILD_ID || !API_KEY || !EXTERNAL_URL || !PASSPORT_API_KEY || !ALCHEMY_BASE_KEY) {
  console.error("Missing environment variables");
  process.exit(1);
}

// ===== ROLE RULES (for UI + auditability) =====
// - Chosen One -> unlocks "the chosen people" channel
// - O.G. HUMN -> unlocks "og humns" channel
// - All covenant roles -> unlock covenant discussion + meme contest channels
const ROLE_RULES = {
  "Covenant Verified Signatory": {
    unlocks: ["covenant discussion", "meme contest"],
    description: "Covenant access"
  },
  "Covenant Signatory O.G.": {
    unlocks: ["covenant discussion", "meme contest"],
    description: "Covenant access (NFT holder)"
  },
  "Chosen One": {
    unlocks: ["the chosen people"],
    description: "Chosen channel access"
  },
  "O.G. HUMN": {
    unlocks: ["og humns"],
    description: "OG HUMN channel access"
  }
};

const API_URL = "http://manifest.human.tech/api/covenant/signers-export";

// ===== EXPRESS SERVER =====
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`HTTP server running on port ${PORT}`));

// ===== DISCORD CLIENT =====
const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });

// ===== CHALLENGES, COOLDOWN, CHANNEL TRACKING =====
const challenges = new Map();
const cooldowns = new Map();
const createdChannels = new Map(); // userId -> channelId
const channelDeleteTimers = new Map(); // userId -> timeout handle (for 10-min auto-delete)
const COOLDOWN_SECONDS = 300;
const CHANNEL_LIFETIME = 10 * 60 * 1000; // 10 minutes (was 15 minutes)
const VERIFIED_CLOSE_MS = 10 * 1000; // 10 seconds (was 8 seconds)


// ===== VERIFIED USER STORE (wallet ↔ discordId) =====
// Small-project friendly JSON store. Swap for Postgres/Redis later if needed.
const VERIFIED_STORE_PATH = process.env.VERIFIED_STORE_PATH || path.join(__dirname, "verified_users.json");

function readVerifiedStore() {
  try {
    const raw = fs.readFileSync(VERIFIED_STORE_PATH, "utf8");
    const data = JSON.parse(raw);
    return data && typeof data === "object" ? data : {};
  } catch (_) {
    return {};
  }
}

function writeVerifiedStore(store) {
  try {
    fs.writeFileSync(VERIFIED_STORE_PATH, JSON.stringify(store, null, 2), "utf8");
  } catch (e) {
    console.error("Failed to write verified store:", e.message);
  }
}

function upsertVerifiedUser(userId, wallet) {
  const store = readVerifiedStore();
  store[userId] = {
    wallet: wallet.toLowerCase(),
    updatedAt: new Date().toISOString()
  };
  writeVerifiedStore(store);
}

function getVerifiedWallet(userId) {
  const store = readVerifiedStore();
  return store?.[userId]?.wallet || null;
}

// ===== CACHES =====
const scoreCache = new Map();
const nftCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

function sleep(ms){return new Promise(r=>setTimeout(r,ms));}

// ===== RETRY HELPER =====
async function retry(fn, retries = 3, delay = 1000) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try { return await fn(); }
    catch (e) { lastError = e; await new Promise(r => setTimeout(r, delay)); }
  }
  throw lastError;
}

// ===== REGISTER /verify SLASH COMMAND =====
(async () => {
  const commands = [
    new SlashCommandBuilder()
      .setName("verify")
      .setDescription("Start wallet verification")
      .addStringOption(opt =>
        opt.setName("wallet")
          .setDescription("Your wallet address")
          .setRequired(true)
      )
  ].map(c => c.toJSON());

  const rest = new REST({ version: "10" }).setToken(TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
  console.log("Slash commands registered");
})();

// ===== HELPERS =====
async function fetchWhitelist() {
  const res = await fetch(`${API_URL}?apiKey=${API_KEY}`);
  const json = await res.json();
  return json.signers || [];
}

async function fetchPassportScore(wallet) {
  const cached = scoreCache.get(wallet);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached.score;

  const url = `https://api.passport.xyz/v2/stamps/9325/score/${wallet}`;
  const score = await retry(async () => {
    const res = await fetch(url, { headers: { "X-API-KEY": PASSPORT_API_KEY } });
    if (!res.ok) throw new Error("Passport API failed");
    const json = await res.json();
    return Number(json.score ?? json?.data?.score ?? 0);
  });

  scoreCache.set(wallet, { score, timestamp: Date.now() });
  return score;
}

// ERC721 ABI
const ERC721_ABI = ["function balanceOf(address owner) view returns (uint256)"];

// ===== ALCHEMY BASE NFT CHECK =====
// Uses Alchemy NFT API (v3) + contract filter to avoid pulling the whole wallet inventory.
// Docs: getNFTsForOwner (v3) supports Base and contractAddresses filtering.
// https://www.alchemy.com/docs/reference/nft-api-endpoints/nft-api-endpoints/nft-ownership-endpoints/get-nf-ts-for-owner-v-3
const BASE_NFT_CONTRACT = "0x89BC14a2fe52Ad7716F7a4a2b54426241CaB71BC".toLowerCase();

async function checkBaseNFTOwnershipAlchemy(wallet) {
  try {
    // Note: Alchemy expects contractAddresses[] repeated query param.
    const url = `https://base-mainnet.g.alchemy.com/nft/v3/${ALCHEMY_BASE_KEY}/getNFTsForOwner?owner=${wallet}&contractAddresses[]=${BASE_NFT_CONTRACT}`;
    const res = await fetch(url);
    const data = await res.json();

    const owned = Array.isArray(data?.ownedNfts) ? data.ownedNfts : [];
    const hasNFT = owned.length > 0; // contractAddresses filter means any result implies ownership

    console.log(`[DEBUG] Alchemy Base NFT check for ${wallet}: ${hasNFT ? "HAS NFT" : "No NFT"}`);
    return hasNFT;
  } catch (err) {
    console.error("[DEBUG] Alchemy Base NFT check failed:", err.message);
    return false;
  }
}

// In-flight guard to prevent duplicate concurrent NFT lookups per wallet
const nftInflight = new Map();

// ===== MULTI-CHAIN NFT CHECK =====
async function checkNFTOwnershipMulti(wallet) {
  // De-dupe concurrent checks for same wallet
  if (nftInflight.has(wallet)) return nftInflight.get(wallet);

  const task = (async () => {
  const cached = nftCache.get(wallet);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached.isHolder;

  let isHolder = false;

  await retry(async () => {
    // Base network using Alchemy API
    try {
      const baseHasNFT = await checkBaseNFTOwnershipAlchemy(wallet);
      if (baseHasNFT) isHolder = true;
    } catch (e) { console.error("Base NFT check failed:", e.message); }

    // Ethereum mainnet (ERC721) with ethers
    try {
      const ethProvider = ALCHEMY_ETH_KEY
        ? new ethers.AlchemyProvider("homestead", ALCHEMY_ETH_KEY)
        : ethers.getDefaultProvider("homestead");
      const ethContract = new ethers.Contract(
        "0xa3c5bb6a34d758fc5d5c656b06b51b4078ba68a8",
        ERC721_ABI,
        ethProvider
      );
      const balance = await ethContract.balanceOf(wallet);
      console.log(`[DEBUG] Ethereum NFT balance for ${wallet}:`, balance.toString());
      // ethers v5 returns BigNumber (has .gt). ethers v6 returns bigint.
      const hasEthNft =
        typeof balance === "bigint"
          ? balance > 0n
          : (balance?.gt?.(0) ?? Number(balance) > 0);
      if (hasEthNft) isHolder = true;
    } catch (e) { console.error("[DEBUG] Ethereum NFT check failed:", e.message); }

    return true;
  });

  nftCache.set(wallet, { isHolder, timestamp: Date.now() });
  return isHolder;
  })();

  nftInflight.set(wallet, task);
  try {
    return await task;
  } finally {
    nftInflight.delete(wallet);
  }
}


// ===== ROLE EVALUATION + APPLY (add/remove) =====
const ROLE_NAMES = {
  covenantVerified: "Covenant Verified Signatory",
  covenantOg: "Covenant Signatory O.G.",
  chosen: "Chosen One",
  ogHumn: "O.G. HUMN"
};

// Pulls assigned roles from Discord member (by name)
function getAssignedRoleNames(member) {
  const names = new Set();
  member.roles.cache.forEach(r => names.add(r.name));
  return names;
}

async function computeEligibility(wallet) {
  const out = {
    passportScore: 0,
    nftHolder: false,
    inManifest: false
  };

  // Manifest check
  try {
    const list = await fetchWhitelist();
    const entry = list.find(w =>
      w.walletAddress?.toLowerCase() === wallet.toLowerCase() &&
      w.covenantStatus?.toUpperCase() === "SIGNED" &&
      w.humanityStatus?.toUpperCase() === "VERIFIED"
    );
    out.inManifest = !!entry;
  } catch (e) {
    console.error("Manifest whitelist fetch failed:", e.message);
  }

  // Passport score
  try { out.passportScore = await fetchPassportScore(wallet); }
  catch (e) { console.error("Passport lookup failed:", e.message); }

  // NFT ownership (either covenant contract)
  try { out.nftHolder = await checkNFTOwnershipMulti(wallet); }
  catch (e) { console.error("NFT ownership check failed:", e.message); }

  return out;
}

async function applyRolesForMember(guild, member, wallet) {
  const roleReport = {
    assignedRoles: [],
    qualifiedRoles: [],
    notAssigned: {},
    unlocks: {},
    inputs: { wallet }
  };

  for (const [roleName, info] of Object.entries(ROLE_RULES)) {
    roleReport.unlocks[roleName] = info.unlocks;
  }

  // If we can't evaluate, we can still report what's currently assigned.
  const current = getAssignedRoleNames(member);

  // Evaluate eligibility (can be slow)
  const eligibility = await computeEligibility(wallet);
  roleReport.inputs.passportScore = eligibility.passportScore;
  roleReport.inputs.nftHolder = eligibility.nftHolder;
  roleReport.inputs.inManifest = eligibility.inManifest;

  // Decide qualifications
  // Covenant Verified Signatory: in manifest (SIGNED + VERIFIED)
  if (eligibility.inManifest) roleReport.qualifiedRoles.push(ROLE_NAMES.covenantVerified);
  else roleReport.notAssigned[ROLE_NAMES.covenantVerified] = "You are not verified as a signatory (not found in the manifest whitelist).";

  // Covenant Signatory O.G.: owns either of the two NFTs
  if (eligibility.nftHolder) roleReport.qualifiedRoles.push(ROLE_NAMES.covenantOg);
  else roleReport.notAssigned[ROLE_NAMES.covenantOg] = "You do not own the limited edition Human Tech Covenant Signatory.";

  // Chosen One: Passport >= 70
  if (eligibility.passportScore >= 70) roleReport.qualifiedRoles.push(ROLE_NAMES.chosen);
  else roleReport.notAssigned[ROLE_NAMES.chosen] = `Passport score ${eligibility.passportScore} < 70`;

  // O.G. HUMN: Passport >= 20
  if (eligibility.passportScore >= 20) roleReport.qualifiedRoles.push(ROLE_NAMES.ogHumn);
  else roleReport.notAssigned[ROLE_NAMES.ogHumn] = `Passport score ${eligibility.passportScore} < 20`;

  // Apply add/remove (only for roles we manage)
  const managed = Object.values(ROLE_NAMES);
  const qualifiedSet = new Set(roleReport.qualifiedRoles);

  for (const roleName of managed) {
    const roleObj = guild.roles.cache.find(r => r.name === roleName);
    if (!roleObj) {
      roleReport.notAssigned[roleName] = roleReport.notAssigned[roleName] || "Role not found in this Discord server";
      continue;
    }

    const hasRole = member.roles.cache.has(roleObj.id);
    const shouldHave = qualifiedSet.has(roleName);

    try {
      if (shouldHave && !hasRole) {
        await member.roles.add(roleObj);
        await sleep(500);
      } else if (!shouldHave && hasRole) {
        await member.roles.remove(roleObj);
        await sleep(500);
      }
    } catch (e) {
      // Don't overwrite a more specific reason
      if (!roleReport.notAssigned[roleName] || roleReport.notAssigned[roleName].startsWith("Passport") || roleReport.notAssigned[roleName].includes("limited edition") || roleReport.notAssigned[roleName].includes("manifest")) {
        roleReport.notAssigned[roleName] = roleReport.notAssigned[roleName];
      } else {
        roleReport.notAssigned[roleName] = `Failed to update role: ${e.message}`;
      }
    }
  }

  // Recompute assigned roles after changes
  const member2 = await guild.members.fetch(member.id);
  const after = getAssignedRoleNames(member2);
  for (const r of managed) {
    if (after.has(r)) roleReport.assignedRoles.push(r);
  }

  return roleReport;
}

// ===== DISCORD EVENTS =====
client.once("ready", async () => {
  console.log(`Logged in as ${client.user.tag}`);

  // ===== AUTO ROLE REFRESH (polling) =====
  // Periodically re-check stored verified users and add/remove roles as needed.
  // This enables automatic revokes if NFTs are sold, without requiring /verify.
  const runRefresh = async () => {
    try {
      const store = readVerifiedStore();
      const guild = client.guilds.cache.get(GUILD_ID);
      const entries = Object.entries(store);
      for (const [uid, info] of entries) {
        const wallet = info?.wallet;
        if (!wallet) continue;
        try {
          const member = await guild.members.fetch(uid);
          await applyRolesForMember(guild, member, wallet);
          await sleep(800);
        } catch (e) {
          // member may have left server
          if (String(e.message || "").includes("Unknown Member")) continue;
          console.error("Auto refresh failed for", uid, e.message);
        }
      }
    } catch (e) {
      console.error("Auto refresh loop error:", e.message);
    }
  };

  // kick once on boot, then interval
  await runRefresh();
  setInterval(runRefresh, Math.max(5, ROLE_REFRESH_MINUTES) * 60 * 1000);
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;

  const guild = interaction.guild;
  const member = interaction.member;

  if (interaction.commandName === "verify") {
    const wallet = interaction.options.getString("wallet").toLowerCase();
    const userId = interaction.user.id.toString();

    await interaction.deferReply({ ephemeral: true });

    const now = Date.now();
    const last = cooldowns.get(userId) || 0;
    if (now - last < COOLDOWN_SECONDS * 1000) {
      const remaining = Math.ceil((COOLDOWN_SECONDS * 1000 - (now - last)) / 1000);
      return interaction.editReply({ content: `⏳ You can verify again in ${remaining} seconds.` });
    }
    cooldowns.set(userId, now);

    const list = await fetchWhitelist();
    const entry = list.find(w =>
      w.walletAddress?.toLowerCase() === wallet &&
      w.covenantStatus?.toUpperCase() === "SIGNED" &&
      w.humanityStatus?.toUpperCase() === "VERIFIED"
    );

    if (!entry) return interaction.editReply({ content: "❌ Wallet not eligible: must be SIGNED + VERIFIED." });

    try {
      const channel = await guild.channels.create({
        name: `verify-${member.user.username}`,
        type: ChannelType.GuildText,
        permissionOverwrites: [
          { id: guild.roles.everyone, deny: [PermissionsBitField.Flags.ViewChannel] },
          { id: member.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages] },
          { id: client.user.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages] }
        ]
      });

      createdChannels.set(userId, channel.id);

      // Auto-delete after 10 minutes if not verified; track timer so we can clear it on success
      const timer = setTimeout(() => {
        const chId = createdChannels.get(userId);
        if (chId) {
          const ch = guild.channels.cache.get(chId);
          if (ch) ch.delete().catch(() => {});
          createdChannels.delete(userId);
          challenges.delete(userId);
        }
        channelDeleteTimers.delete(userId);
      }, CHANNEL_LIFETIME);

      channelDeleteTimers.set(userId, timer);

      const challenge = `Verify ownership for ${wallet} at ${Date.now()}`;
      challenges.set(userId, { challenge, wallet, channelId: channel.id });

      const signerUrl = `${EXTERNAL_URL.replace(/\/$/, "")}/signer.html?userId=${userId}&challenge=${encodeURIComponent(challenge)}`;

      await channel.send(`
# human.tech Role Verification

Click the link to connect your wallet and sign:

🔗 ${signerUrl}
      `);

      return interaction.editReply({ content: `✅ Private verification channel created: ${channel}` });

    } catch (err) {
      console.error(err);
      return interaction.editReply({ content: "❌ Failed to create verification channel." });
    }
  }
});

// ===== SIGNATURE ENDPOINT =====
app.post("/api/signature", async (req, res) => {
  const { userId, signature } = req.body;
  if (!userId || !signature) return res.status(400).json({ error: "Missing userId or signature" });

  const data = challenges.get(userId.toString());
  if (!data) return res.status(400).json({ error: "No active verification" });

  try {
    const recovered = ethers.verifyMessage(data.challenge, signature);
    if (recovered.toLowerCase() !== data.wallet.toLowerCase())
      return res.status(400).json({ error: "Signature mismatch" });

    // Clear the 10-minute auto-delete timer to avoid race/double deletes
    const t = channelDeleteTimers.get(userId.toString());
    if (t) clearTimeout(t);
    channelDeleteTimers.delete(userId.toString());

    const guild = client.guilds.cache.get(GUILD_ID);
    const member = await guild.members.fetch(userId);

    // Persist wallet ↔ user mapping for status/refresh/webhooks
    upsertVerifiedUser(userId.toString(), data.wallet);    // ===== ROLE DECISION / AUDIT =====
    const roleReport = await applyRolesForMember(guild, member, data.wallet);

    // Send results in private channel
    const channel = guild.channels.cache.get(data.channelId);
    if (channel) {
      await channel.send(
        `✅ **Wallet verified**\n\n` +
        `🧮 Passport score: **${Number(roleReport?.inputs?.passportScore ?? 0)}**\n` +
        `🎨 NFT holder: **${(roleReport?.inputs?.nftHolder) ? "Yes" : "No"}**\n` +
        `🏷 Roles granted: **${roleReport.assignedRoles.join(", ") || "None"}**\n\n` +
        `**Role status:**\n` +
        Object.keys(ROLE_RULES).map(rn => {
          if (roleReport.assignedRoles.includes(rn)) return `✅ ${rn} — unlocks ${ROLE_RULES[rn].unlocks.join(" + ")}`;
          const reason = roleReport.notAssigned[rn] || "Not assigned";
          return `❌ ${rn} — ${reason} — unlocks ${ROLE_RULES[rn].unlocks.join(" + ")}`;
        }).join("\n") +
        `\n\n` +
        `Channel will close shortly…`
      );
      setTimeout(() => channel.delete().catch(() => {}), VERIFIED_CLOSE_MS);
      createdChannels.delete(userId);
    }

    challenges.delete(userId);

    return res.json({
      success: true,
      score: Number(roleReport?.inputs?.passportScore ?? 0),
      nft: Boolean(roleReport?.inputs?.nftHolder),
      roles: roleReport.assignedRoles,
      assignedRoles: roleReport.assignedRoles,
      qualifiedRoles: roleReport.qualifiedRoles,
      notAssigned: roleReport.notAssigned,
      unlocks: roleReport.unlocks,
      inputs: roleReport.inputs
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Verification failed" });
  }
});


// ===== STATUS ENDPOINT (no signing needed) =====
// Returns current assigned roles (and eligibility if we have a stored wallet)
app.get("/api/status", async (req, res) => {
  const userId = (req.query.userId || "").toString();
  if (!userId) return res.status(400).json({ success: false, error: "Missing userId" });

  try {
    const guild = client.guilds.cache.get(GUILD_ID);
    const member = await guild.members.fetch(userId);

    const assigned = [];
    const managed = ["Covenant Verified Signatory", "Covenant Signatory O.G.", "Chosen One", "O.G. HUMN"];
    for (const rn of managed) {
      const roleObj = guild.roles.cache.find(r => r.name === rn);
      if (roleObj && member.roles.cache.has(roleObj.id)) assigned.push(rn);
    }

    // If there's an active /verify session, surface the expected wallet and DO NOT
    // reconcile/assign roles without a fresh signature.
    const active = challenges.get(userId.toString());
    if (active && active.wallet) {
      return res.json({
        success: true,
        activeVerification: true,
        assignedRoles: assigned,
        qualifiedRoles: [],
        notAssigned: {},
        unlocks: Object.fromEntries(Object.entries(ROLE_RULES).map(([k,v]) => [k, v.unlocks])),
        inputs: { wallet: active.wallet.toLowerCase() }
      });
    }

    const wallet = getVerifiedWallet(userId);

    // If we have a wallet, compute eligibility + reasons and (optionally) reconcile roles
    if (wallet) {
      const roleReport = await applyRolesForMember(guild, member, wallet);
      return res.json({
        success: true,
        assignedRoles: roleReport.assignedRoles,
        qualifiedRoles: roleReport.qualifiedRoles,
        notAssigned: roleReport.notAssigned,
        unlocks: roleReport.unlocks,
        inputs: roleReport.inputs
      });
    }

    // No wallet known: just return assigned roles
    return res.json({
      success: true,
      assignedRoles: assigned,
      qualifiedRoles: [],
      notAssigned: {},
      unlocks: Object.fromEntries(Object.entries(ROLE_RULES).map(([k,v]) => [k, v.unlocks])),
      inputs: { wallet: null }
    });
  } catch (e) {
    console.error("Status endpoint failed:", e.message);
    return res.status(500).json({ success: false, error: "Failed to fetch status" });
  }
});




// ===== CONFIRM WALLET ENDPOINT (no re-sign needed for same wallet) =====
// If the user has an active /verify session and connects the SAME wallet, we can:
// - persist the wallet
// - clear the active challenge session
// - reconcile roles immediately
// Returns which roles were newly added by the reconciliation.
app.post("/api/confirm-wallet", async (req, res) => {
  const userId = (req.body?.userId || "").toString();
  const wallet = (req.body?.wallet || "").toString().toLowerCase();

  if (!userId) return res.status(400).json({ success: false, error: "Missing userId" });
  if (!wallet) return res.status(400).json({ success: false, error: "Missing wallet" });

  try {
    const active = challenges.get(userId.toString());
    if (!active || !active.wallet) {
      return res.status(400).json({ success: false, error: "No active verification session" });
    }

    const expected = active.wallet.toString().toLowerCase();
    if (wallet !== expected) {
      return res.status(400).json({
        success: false,
        error: "Wallet mismatch",
        expectedWallet: expected,
        receivedWallet: wallet
      });
    }

    const guild = client.guilds.cache.get(GUILD_ID);
    const member = await guild.members.fetch(userId);

    // Snapshot current assigned roles (managed set only)
    const managed = ["Covenant Verified Signatory", "Covenant Signatory O.G.", "Chosen One", "O.G. HUMN"];
    const assignedBefore = [];
    for (const rn of managed) {
      const roleObj = guild.roles.cache.find(r => r.name === rn);
      if (roleObj && member.roles.cache.has(roleObj.id)) assignedBefore.push(rn);
    }

    // Persist wallet and end the active verification session
    upsertVerifiedUser(userId, wallet);
    challenges.delete(userId.toString());

    // Reconcile roles
    const roleReport = await applyRolesForMember(guild, member, wallet);
    const addedRoles = roleReport.assignedRoles.filter(r => !assignedBefore.includes(r));

    return res.json({
      success: true,
      sameWallet: true,
      addedRoles,
      assignedRoles: roleReport.assignedRoles,
      qualifiedRoles: roleReport.qualifiedRoles,
      notAssigned: roleReport.notAssigned,
      unlocks: roleReport.unlocks,
      inputs: roleReport.inputs
    });
  } catch (e) {
    console.error("confirm-wallet failed:", e.message);
    return res.status(500).json({ success: false, error: "Failed to confirm wallet" });
  }
});

// ===== ALCHEMY WEBHOOK (NFT transfers → revoke/grant Covenant Signatory O.G.) =====
// Configure Alchemy Notify webhooks for:
// - Ethereum mainnet contract: 0xa3c5bb6a34d758fc5d5c656b06b51b4078ba68a8
// - Base mainnet contract:    0x89BC14a2fe52Ad7716F7a4a2b54426241CaB71BC
//
// Set ALCHEMY_WEBHOOK_SIGNING_KEY to verify requests (recommended).
const rawJson = express.raw({ type: "application/json" });

function verifyAlchemySignature(rawBody, signatureHeader) {
  if (!ALCHEMY_WEBHOOK_SIGNING_KEY) return true; // allow if no signing key configured
  if (!signatureHeader) return false;
  // Alchemy signs with HMAC-SHA256 of the raw request body using the signing key
  const expected = crypto.createHmac("sha256", ALCHEMY_WEBHOOK_SIGNING_KEY).update(rawBody).digest("hex");
  // Header formats can vary; accept exact hex match or "sha256=<hex>"
  const sig = signatureHeader.toString().replace(/^sha256=/i, "").trim();
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(sig, "hex"));
}

app.post("/api/alchemy/webhook", rawJson, async (req, res) => {
  try {
    const sigHeader = req.headers["x-alchemy-signature"] || req.headers["alchemy-signature"] || req.headers["x-signature"];
    const rawBody = req.body; // Buffer
    if (!verifyAlchemySignature(rawBody, sigHeader)) {
      return res.status(401).send("invalid signature");
    }

    const payload = JSON.parse(rawBody.toString("utf8"));
    const activities = payload?.event?.activity || payload?.activity || payload?.activities || [];
    const addrs = new Set();

    for (const a of activities) {
      const from = (a?.fromAddress || a?.from || "").toLowerCase();
      const to = (a?.toAddress || a?.to || "").toLowerCase();
      if (from) addrs.add(from);
      if (to) addrs.add(to);
    }

    // Map wallet addresses → discord IDs via store and refresh those users
    const store = readVerifiedStore();
    const walletToUser = new Map();
    for (const [uid, info] of Object.entries(store)) {
      if (info?.wallet) walletToUser.set(info.wallet.toLowerCase(), uid);
    }

    const guild = client.guilds.cache.get(GUILD_ID);
    const refreshed = [];

    for (const addr of addrs) {
      const uid = walletToUser.get(addr);
      if (!uid) continue;
      try {
        const member = await guild.members.fetch(uid);
        const report = await applyRolesForMember(guild, member, addr);
        refreshed.push({ userId: uid, wallet: addr, assignedRoles: report.assignedRoles });
      } catch (e) {
        console.error("Webhook refresh failed for", addr, e.message);
      }
    }

    return res.json({ ok: true, refreshed });
  } catch (e) {
    console.error("Alchemy webhook handler failed:", e.message);
    return res.status(500).send("error");
  }
});


client.login(TOKEN);
