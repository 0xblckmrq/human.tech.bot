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

process.on("unhandledRejection", err => {
  console.error("UnhandledRejection:", err);
});
process.on("uncaughtException", err => {
  console.error("UncaughtException:", err);
});

// ===== CONFIG =====
const TOKEN = process.env.BOT_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const GUILD_ID = process.env.GUILD_ID;
const API_KEY = process.env.WHITELIST_API_KEY;
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL;
const PASSPORT_API_KEY = process.env.PASSPORT_API_KEY;
const ALCHEMY_BASE_KEY = process.env.ALCHEMY_BASE_KEY; // Alchemy Base (NFT API)
const ALCHEMY_ETH_KEY = process.env.ALCHEMY_ETH_KEY;
const ETH_MAINNET = { name: "homestead", chainId: 1 }; // Pin network to avoid detect-network spam
const ALCHEMY_WEBHOOK_SIGNING_KEY = process.env.ALCHEMY_WEBHOOK_SIGNING_KEY; // Optional: verify Alchemy webhook signatures
// Default polling to 12h when webhooks are configured; override with ROLE_REFRESH_MINUTES.
const ROLE_REFRESH_MINUTES = Number(process.env.ROLE_REFRESH_MINUTES || 720);
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
  "Covenant Contributor": {
    unlocks: ["covenant discussion", "meme contest"],
    description: "Covenant access (Contributor NFT holder)"
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
// Match typical refresh cadence to reduce provider/API calls.
const CACHE_TTL = 60 * 60 * 1000; 
const ONE_DAY_MS = 24 * 60 * 60 * 1000;
function rateLimitMeta(message) {
  return {
    message: message || "Temporarily unavailable.",
    retryAfterSeconds: 86400,
    retryAfterAt: Date.now() + ONE_DAY_MS
  };
}
// 1 hour

function sleep(ms){return new Promise(r=>setTimeout(r,ms));}

function isRateLimitError(e) {
  const msg = String(e?.message || "");
  return msg.includes("429") || msg.toLowerCase().includes("capacity limit") || msg.toLowerCase().includes("too many requests");
}

// ===== RETRY HELPER =====
async function retry(fn, retries = 3, delay = 1000) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try { return await fn(); }
    catch (e) {
      lastError = e;
      // Do not retry hard rate limits / exhausted quota.
      if (isRateLimitError(e)) throw e;
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastError;
}

// ===== ETH RPC PROVIDER (FALLBACK) =====
// Supports env override via ETH_RPC_URLS="url1,url2" (optional).
function getEthProvider() {
  const urlsFromEnv = String(process.env.ETH_RPC_URLS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  // Prefer free/public RPCs first; keep Alchemy as last fallback (if key is set).
  const defaultUrls = [
    "https://cloudflare-eth.com",
    "https://rpc.ankr.com/eth",
    ...(ALCHEMY_ETH_KEY ? [`https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_ETH_KEY}`] : [])
  ];

  const urls = urlsFromEnv.length ? urlsFromEnv : defaultUrls;

  // Pin chainId=1 to avoid noisy network detection retries.
  const providers = urls.map(u => new ethers.JsonRpcProvider(u, ETH_MAINNET));

  if (providers.length === 1) return providers[0];

  // quorum=1: any one healthy provider response is enough.
  return new ethers.FallbackProvider(providers, 1);
}

// Create singleton ETH provider
const ETH_PROVIDER = getEthProvider();

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

// ===== CONTRIBUTOR NFT CHECK (ETH MAINNET) =====
const CONTRIBUTOR_NFT_CONTRACT = "0x25e580d1113d040af6bc2edd626cf50348973c70".toLowerCase();

async function checkContributorNFTOwnershipEth(wallet) {
  try {
    const ethProvider = ETH_PROVIDER;
    const contributorContract = new ethers.Contract(
      CONTRIBUTOR_NFT_CONTRACT,
      ERC721_ABI,
      ethProvider
    );
    const balance = await contributorContract.balanceOf(wallet);
    console.log(`[DEBUG] Contributor NFT balance for ${wallet}:`, balance.toString());
    const hasContributorNft =
      typeof balance === "bigint"
        ? balance > 0n
        : (balance?.gt?.(0) ?? Number(balance) > 0);
    return hasContributorNft;
  } catch (e) {
    console.error("[DEBUG] Contributor NFT check failed:", e.message);
    // Unknown (do not revoke on provider failure)
    return null;
  }
}


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

    const text = await res.text();

    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      console.error("[DEBUG] Alchemy Base returned non-JSON:", text.slice(0, 200));
      return null;
    }

    if (!res.ok) {
      console.error("[DEBUG] Alchemy Base error:", data);
      // Treat rate limits / quota exhaustion as unknown.
      if (res.status === 429 || String(data?.error?.message || "").toLowerCase().includes("capacity")) return null;
      return null;
    }

    const owned = Array.isArray(data?.ownedNfts) ? data.ownedNfts : [];
    const hasNFT = owned.length > 0; // contractAddresses filter means any result implies ownership

    console.log(`[DEBUG] Alchemy Base NFT check for ${wallet}: ${hasNFT ? "HAS NFT" : "No NFT"}`);
    return hasNFT;
  } catch (err) {
    console.error("[DEBUG] Alchemy Base NFT check failed:", err.message);
    return null;
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

  let anyUnknown = false;

  // Base network using Alchemy API
  let baseHasNFT = null;
  try { baseHasNFT = await checkBaseNFTOwnershipAlchemy(wallet); }
  catch (e) { console.error("Base NFT check failed:", e.message); baseHasNFT = null; }
  if (baseHasNFT === true) {
    nftCache.set(wallet, { isHolder: true, timestamp: Date.now() });
    return true;
  }
  if (baseHasNFT === null) anyUnknown = true;

  // Ethereum mainnet (ERC721) with fallback provider
  let ethHasNFT = null;
  try {
    const ethProvider = ETH_PROVIDER;
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
    ethHasNFT = hasEthNft;
  } catch (e) {
    console.error("[DEBUG] Ethereum NFT check failed:", e.message);
    ethHasNFT = null;
  }
  if (ethHasNFT === true) {
    nftCache.set(wallet, { isHolder: true, timestamp: Date.now() });
    return true;
  }
  if (ethHasNFT === null) anyUnknown = true;

  const final = anyUnknown ? null : false;
  nftCache.set(wallet, { isHolder: final, timestamp: Date.now() });
  return final;
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
  covenantContributor: "Covenant Contributor",
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
    passportScore: null,
    nftHolder: null,
    contributorHolder: null,
    inManifest: null
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
    out.inManifest = null;
  }

  // Passport score
  try { out.passportScore = await fetchPassportScore(wallet); }
  catch (e) { console.error("Passport lookup failed:", e.message); out.passportScore = null; }

  // NFT ownership (OG covenant contract)
  try { out.nftHolder = await checkNFTOwnershipMulti(wallet); }
  catch (e) { console.error("NFT ownership check failed:", e.message); out.nftHolder = null; }

  // Contributor NFT ownership (ETH mainnet)
  try { out.contributorHolder = await checkContributorNFTOwnershipEth(wallet); }
  catch (e) { console.error("Contributor NFT ownership check failed:", e.message); out.contributorHolder = null; }

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
  roleReport.inputs.contributorHolder = eligibility.contributorHolder;
  roleReport.inputs.inManifest = eligibility.inManifest;

  // Decide desired role states (true/false/null). null => unknown, do not revoke.
  const desired = {};

  // Covenant Verified Signatory: in manifest (SIGNED + VERIFIED)
  if (eligibility.inManifest === true) desired[ROLE_NAMES.covenantVerified] = true;
  else if (eligibility.inManifest === false) {
    desired[ROLE_NAMES.covenantVerified] = false;
    roleReport.notAssigned[ROLE_NAMES.covenantVerified] = "You are not verified as a signatory (not found in the manifest whitelist).";
  } else {
    desired[ROLE_NAMES.covenantVerified] = null;
    roleReport.notAssigned[ROLE_NAMES.covenantVerified] = rateLimitMeta("Temporarily unable to verify manifest status (provider rate-limited).");
  }

  // Covenant Signatory O.G.: holds OG NFTs (Base and/or ETH)
  if (eligibility.nftHolder === true) desired[ROLE_NAMES.covenantOg] = true;
  else if (eligibility.nftHolder === false) {
    desired[ROLE_NAMES.covenantOg] = false;
    roleReport.notAssigned[ROLE_NAMES.covenantOg] = "You do not own the limited edition Human Tech Covenant Signatory.";
  } else {
    desired[ROLE_NAMES.covenantOg] = null;
    roleReport.notAssigned[ROLE_NAMES.covenantOg] = rateLimitMeta("Temporarily unable to verify NFT ownership (provider rate-limited).");
  }

  // Covenant Contributor: holds Contributor NFT (ETH)
  if (eligibility.contributorHolder === true) desired[ROLE_NAMES.covenantContributor] = true;
  else if (eligibility.contributorHolder === false) {
    desired[ROLE_NAMES.covenantContributor] = false;
    roleReport.notAssigned[ROLE_NAMES.covenantContributor] = "You do not own the Human Tech Covenant Contributor NFT.";
  } else {
    desired[ROLE_NAMES.covenantContributor] = null;
    roleReport.notAssigned[ROLE_NAMES.covenantContributor] = rateLimitMeta("Temporarily unable to verify Contributor NFT (provider rate-limited).");
  }

  // Chosen One: Passport >= 70
  if (typeof eligibility.passportScore === "number") {
    if (eligibility.passportScore >= 70) desired[ROLE_NAMES.chosen] = true;
    else {
      desired[ROLE_NAMES.chosen] = false;
      roleReport.notAssigned[ROLE_NAMES.chosen] = `Passport score ${eligibility.passportScore} < 70`;
    }
  } else {
    desired[ROLE_NAMES.chosen] = null;
    roleReport.notAssigned[ROLE_NAMES.chosen] = rateLimitMeta("Temporarily unable to fetch Passport score (provider rate-limited).");
  }

  // O.G. HUMN: Passport >= 20
  if (typeof eligibility.passportScore === "number") {
    if (eligibility.passportScore >= 20) desired[ROLE_NAMES.ogHumn] = true;
    else {
      desired[ROLE_NAMES.ogHumn] = false;
      roleReport.notAssigned[ROLE_NAMES.ogHumn] = `Passport score ${eligibility.passportScore} < 20`;
    }
  } else {
    desired[ROLE_NAMES.ogHumn] = null;
    roleReport.notAssigned[ROLE_NAMES.ogHumn] = rateLimitMeta("Temporarily unable to fetch Passport score (provider rate-limited).");
  }

  // qualifiedRoles = those explicitly true
  for (const [rn, v] of Object.entries(desired)) {
    if (v === true) roleReport.qualifiedRoles.push(rn);
  }

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
    const desiredState = Object.prototype.hasOwnProperty.call(desired, roleName)
      ? desired[roleName]
      : (shouldHave ? true : false);

    try {
      if (desiredState === true && !hasRole) {
        await member.roles.add(roleObj);
        await sleep(500);
      } else if (desiredState === false && hasRole) {
        await member.roles.remove(roleObj);
        await sleep(500);
      } else {
        // desiredState === null => unknown; do nothing (no revoke)
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
client.once("clientReady", async () => {
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

try {
  if (!interaction.deferred && !interaction.replied) {
    await interaction.deferReply({ flags: 64 });
  }
} catch (err) {
  if (err?.code === 10062) return;
  console.error("deferReply failed:", err);
  return;
}

    const now = Date.now();
    const last = cooldowns.get(userId) || 0;
    if (now - last < COOLDOWN_SECONDS * 1000) {
      const remaining = Math.ceil((COOLDOWN_SECONDS * 1000 - (now - last)) / 1000);
      return interaction.editReply({ content: `⏳ You can verify again in ${remaining} seconds.` });
    }
    cooldowns.set(userId, now);

    // Fast-path: if this user has already verified this SAME wallet before, refresh roles immediately.
    // Return results ephemerally (no private channel) to avoid clutter.
    const storedWallet = getVerifiedWallet(userId);
    if (storedWallet && storedWallet.toLowerCase() === wallet) {
      try {
        const member2 = await guild.members.fetch(userId);
        const roleReport = await applyRolesForMember(guild, member2, wallet);

        const roleLines = Object.keys(ROLE_RULES).map(rn => {
          if (roleReport.assignedRoles.includes(rn)) return `✅ ${rn} — unlocks ${ROLE_RULES[rn].unlocks.join(" + ")}`;
          const reason = roleReport.notAssigned[rn] || "Not assigned";
          return `❌ ${rn} — ${reason} — unlocks ${ROLE_RULES[rn].unlocks.join(" + ")}`;
        }).join("\n");

        return interaction.editReply({
          content:
            `✅ **Roles refreshed (no re-sign needed)**\n\n` +
            `🔗 Wallet: **${wallet}**\n` +
            `🧮 Passport score: **${(typeof roleReport?.inputs?.passportScore === "number") ? roleReport.inputs.passportScore : "Unknown"}**\n` +
            `🎨 NFT holder: **${(roleReport?.inputs?.nftHolder === true) ? "Yes" : (roleReport?.inputs?.nftHolder === false ? "No" : "Unknown")}**\n` +
            `🏷 Roles granted: **${roleReport.assignedRoles.join(", ") || "None"}**\n\n` +
            `**Role status:**\n${roleLines}`
        });
      } catch (e) {
        console.error("Same-wallet refresh failed:", e.message);
        return interaction.editReply({ content: "❌ Failed to refresh roles. Please try again shortly." });
      }
    }

    const list = await fetchWhitelist();    const entry = list.find(w =>
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
        `🧮 Passport score: **${(typeof roleReport?.inputs?.passportScore === "number") ? roleReport.inputs.passportScore : "Unknown"}**\n` +
        `🎨 NFT holder: **${(roleReport?.inputs?.nftHolder === true) ? "Yes" : (roleReport?.inputs?.nftHolder === false ? "No" : "Unknown")}**\n` +
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
      score: (typeof roleReport?.inputs?.passportScore === "number") ? roleReport.inputs.passportScore : null,
      nft: (roleReport?.inputs?.nftHolder === true) ? true : (roleReport?.inputs?.nftHolder === false ? false : null),
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


// ===== VERIFICATION SESSION MANAGEMENT (for signer UI) =====
// Allows users to restart verification from the signer page without the bot getting "stuck".
//
// - /api/start-verification: (re)starts a verification session for a wallet
//   * clears any existing pending session for the user
//   * validates eligibility (SIGNED + VERIFIED)
//   * returns a fresh challenge to sign
//
// - /api/cancel-verification: cancels an active verification session for the user
//   * does NOT delete their stored verified wallet; it only clears the in-flight challenge

app.post("/api/start-verification", async (req, res) => {
  const userId = (req.body?.userId || "").toString();
  const wallet = (req.body?.wallet || "").toString().toLowerCase();

  if (!userId) return res.status(400).json({ success: false, error: "Missing userId" });
  if (!wallet) return res.status(400).json({ success: false, error: "Missing wallet" });

  try {
    // Preserve any existing channelId (if started via /verify) and clear any in-flight session.
    const prev = challenges.get(userId);
    challenges.delete(userId);

    // Eligibility gate (same as /verify flow)
    const list = await fetchWhitelist();
    const entry = list.find(w =>
      w.walletAddress?.toLowerCase() === wallet &&
      w.covenantStatus?.toUpperCase() === "SIGNED" &&
      w.humanityStatus?.toUpperCase() === "VERIFIED"
    );

    if (!entry) {
      return res.status(400).json({
        success: false,
        error: "Wallet not eligible: must be SIGNED + VERIFIED."
      });
    }

    const challenge = `Verify ownership for ${wallet} at ${Date.now()}`;
    challenges.set(userId, { challenge, wallet, channelId: prev?.channelId || null });

    return res.json({
      success: true,
      userId,
      wallet,
      challenge
    });
  } catch (e) {
    console.error("start-verification failed:", e.message);
    return res.status(500).json({ success: false, error: "Failed to start verification" });
  }
});

app.post("/api/cancel-verification", async (req, res) => {
  const userId = (req.body?.userId || "").toString();
  if (!userId) return res.status(400).json({ success: false, error: "Missing userId" });

  try {
    challenges.delete(userId);
    return res.json({ success: true });
  } catch (e) {
    console.error("cancel-verification failed:", e.message);
    return res.status(500).json({ success: false, error: "Failed to cancel verification" });
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
    const managed = ["Covenant Verified Signatory", "Covenant Signatory O.G.", "Covenant Contributor", "Chosen One", "O.G. HUMN"];
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




// ===== CONFIRM WALLET ENDPOINT (same wallet, no re-sign) =====
// Allows the signer UI to refresh roles immediately when a user reconnects the SAME wallet.
// This does NOT change the linked wallet; it only refreshes roles for the wallet already on record.
app.post("/api/confirm-wallet", async (req, res) => {
  const userId = (req.body?.userId || "").toString();
  const wallet = (req.body?.wallet || "").toString().toLowerCase();

  if (!userId) return res.status(400).json({ success: false, error: "Missing userId" });
  if (!wallet) return res.status(400).json({ success: false, error: "Missing wallet" });

  try {
    const storedWallet = getVerifiedWallet(userId);
    if (!storedWallet) {
      return res.status(400).json({
        success: false,
        error: "No wallet on record. Please run /verify first."
      });
    }

    if (storedWallet.toLowerCase() !== wallet) {
      return res.status(400).json({
        success: false,
        error: "Wallet mismatch. Please use Change or reconnect wallet and sign again."
      });
    }

    const guild = client.guilds.cache.get(GUILD_ID);
    const member = await guild.members.fetch(userId);

    const before = getAssignedRoleNames(member);
    const roleReport = await applyRolesForMember(guild, member, wallet);
    const addedRoles = roleReport.assignedRoles.filter(r => !before.has(r));

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
    return res.status(500).json({ success: false, error: "Failed to refresh roles" });
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
