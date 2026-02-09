require("dotenv").config();
const path = require("path");
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
const ALCHEMY_ETH_KEY = process.env.ALCHEMY_ETH_KEY; // Optional: Alchemy Ethereum RPC key to avoid throttled default providers

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

// ===== CACHES =====
const scoreCache = new Map();
const nftCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

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

// ===== DISCORD EVENTS =====
client.once("ready", () => console.log(`Logged in as ${client.user.tag}`));

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

    // ===== ROLE DECISION / AUDIT =====
    // We'll return structured role info so signer.html can show:
    // - which roles are qualified
    // - which were assigned
    // - which were not assigned + why
    const roleReport = {
      assignedRoles: [],
      qualifiedRoles: [],
      notAssigned: {}, // roleName -> reason
      unlocks: {}, // roleName -> [channels]
      inputs: {}
    };

    for (const [roleName, info] of Object.entries(ROLE_RULES)) {
      roleReport.unlocks[roleName] = info.unlocks;
    }

    // Covenant Verified Signatory (eligible because /verify already required SIGNED + VERIFIED)
    roleReport.qualifiedRoles.push("Covenant Verified Signatory");
    const baseRole = guild.roles.cache.find(r => r.name === "Covenant Verified Signatory");
    if (!baseRole) {
      roleReport.notAssigned["Covenant Verified Signatory"] = "Role not found in this Discord server";
    } else {
      try {
        await member.roles.add(baseRole);
        roleReport.assignedRoles.push(baseRole.name);
      } catch (e) {
        roleReport.notAssigned[baseRole.name] = `Failed to assign role: ${e.message}`;
      }
    }

    // Passport score roles
    let score = 0;
    try { score = await fetchPassportScore(data.wallet); }
    catch (e) { console.error("Passport lookup failed:", e.message); }

    roleReport.inputs.passportScore = score;

    // Chosen One (Passport score >= 70)
    if (score >= 70) {
      roleReport.qualifiedRoles.push("Chosen One");
      const chosen = guild.roles.cache.find(r => r.name === "Chosen One");
      if (!chosen) {
        roleReport.notAssigned["Chosen One"] = "Role not found in this Discord server";
      } else {
        try {
          await member.roles.add(chosen);
          roleReport.assignedRoles.push(chosen.name);
        } catch (e) {
          roleReport.notAssigned[chosen.name] = `Failed to assign role: ${e.message}`;
        }
      }
    } else {
      roleReport.notAssigned["Chosen One"] = `Passport score ${score} < 70`;
    }

    // O.G. HUMN (Passport score >= 20)
    if (score >= 20) {
      roleReport.qualifiedRoles.push("O.G. HUMN");
      const og = guild.roles.cache.find(r => r.name === "O.G. HUMN");
      if (!og) {
        roleReport.notAssigned["O.G. HUMN"] = "Role not found in this Discord server";
      } else {
        try {
          await member.roles.add(og);
          roleReport.assignedRoles.push(og.name);
        } catch (e) {
          roleReport.notAssigned[og.name] = `Failed to assign role: ${e.message}`;
        }
      }
    } else {
      roleReport.notAssigned["O.G. HUMN"] = `Passport score ${score} < 20`;
    }

    // Multi-chain NFT role
    let isNftHolder = false;
    try { isNftHolder = await checkNFTOwnershipMulti(data.wallet); }
    catch (e) { console.error("NFT ownership check failed:", e.message); }

    roleReport.inputs.nftHolder = isNftHolder;

    if (isNftHolder) {
      roleReport.qualifiedRoles.push("Covenant Signatory O.G.");
      const ogRole = guild.roles.cache.find(r => r.name === "Covenant Signatory O.G.");
      if (!ogRole) {
        roleReport.notAssigned["Covenant Signatory O.G."] = "Role not found in this Discord server";
      } else {
        try {
          await member.roles.add(ogRole);
          roleReport.assignedRoles.push(ogRole.name);
        } catch (e) {
          roleReport.notAssigned[ogRole.name] = `Failed to assign role: ${e.message}`;
        }
      }
    } else {
      roleReport.notAssigned["Covenant Signatory O.G."] = "No qualifying NFT found on Base or Ethereum";
    }

    // Send results in private channel
    const channel = guild.channels.cache.get(data.channelId);
    if (channel) {
      await channel.send(
        `✅ **Wallet verified**\n\n` +
        `🧮 Passport score: **${score}**\n` +
        `🎨 NFT holder: **${isNftHolder ? "Yes" : "No"}**\n` +
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
      score,
      nft: isNftHolder,
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

client.login(TOKEN);
