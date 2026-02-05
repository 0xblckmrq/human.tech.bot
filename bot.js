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
const ALCHEMY_BASE_KEY = process.env.ALCHEMY_BASE_KEY; // Alchemy Base RPC

if (!TOKEN || !CLIENT_ID || !GUILD_ID || !API_KEY || !EXTERNAL_URL || !PASSPORT_API_KEY || !ALCHEMY_BASE_KEY) {
  console.error("Missing environment variables");
  process.exit(1);
}

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
async function checkBaseNFVOwnershipAlchemy(wallet) {
  try {
    const url = `https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_BASE_KEY}/getNFTs/?owner=${wallet}`;
    const res = await fetch(url);
    const data = await res.json();

    if (!data.ownedNfts) return false;

    const baseNFTContract = "0x89BC14a2fe52Ad7716F7a4a2b54426241CaB71BC".toLowerCase();
    const hasNFT = data.ownedNfts.some(nft => nft.contract.address.toLowerCase() === baseNFTContract);

    console.log(`[DEBUG] Alchemy Base NFT check for ${wallet}: ${hasNFT ? "HAS NFT" : "No NFT"}`);
    return hasNFT;
  } catch (err) {
    console.error("[DEBUG] Alchemy Base NFT check failed:", err.message);
    return false;
  }
}

// ===== MULTI-CHAIN NFT CHECK =====
async function checkNFTOwnershipMulti(wallet) {
  const cached = nftCache.get(wallet);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached.isHolder;

  let isHolder = false;

  await retry(async () => {
    // Base network using Alchemy API
    try {
      const baseHasNFT = await checkBaseNFVOwnershipAlchemy(wallet);
      if (baseHasNFT) isHolder = true;
    } catch (e) { console.error("Base NFT check failed:", e.message); }

    // Ethereum mainnet (ERC721) with ethers
    try {
      const ethProvider = ethers.getDefaultProvider("homestead");
      const ethContract = new ethers.Contract(
        "0xa3c5bb6a34d758fc5d5c656b06b51b4078ba68a8",
        ERC721_ABI,
        ethProvider
      );
      const balance = await ethContract.balanceOf(wallet);
      console.log(`[DEBUG] Ethereum NFT balance for ${wallet}:`, balance.toString());
      if (balance.gt(0)) isHolder = true;
    } catch (e) { console.error("[DEBUG] Ethereum NFT check failed:", e.message); }

    return true;
  });

  nftCache.set(wallet, { isHolder, timestamp: Date.now() });
  return isHolder;
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

    const grantedRoles = [];

    // Covenant Verified Signatory
    const baseRole = guild.roles.cache.find(r => r.name === "Covenant Verified Signatory");
    if (baseRole) { await member.roles.add(baseRole); grantedRoles.push(baseRole.name); }

    // Passport score roles
    let score = 0;
    try { score = await fetchPassportScore(data.wallet); }
    catch (e) { console.error("Passport lookup failed:", e.message); }

    if (score >= 70) {
      const chosen = guild.roles.cache.find(r => r.name === "Chosen One");
      if (chosen) { await member.roles.add(chosen); grantedRoles.push(chosen.name); }
    }

    if (score >= 20) {
      const og = guild.roles.cache.find(r => r.name === "O.G. HUMN");
      if (og) { await member.roles.add(og); grantedRoles.push(og.name); }
    }

    // Multi-chain NFT role
    let isNftHolder = false;
    try { isNftHolder = await checkNFTOwnershipMulti(data.wallet); }
    catch (e) { console.error("NFT ownership check failed:", e.message); }

    if (isNftHolder) {
      const ogRole = guild.roles.cache.find(r => r.name === "Covenant Signatory O.G.");
      if (ogRole) { await member.roles.add(ogRole); grantedRoles.push(ogRole.name); }
    }

    // Send results in private channel
    const channel = guild.channels.cache.get(data.channelId);
    if (channel) {
      await channel.send(
        `✅ **Wallet verified**\n\n` +
        `🧮 Passport score: **${score}**\n` +
        `🎨 NFT holder: **${isNftHolder ? "Yes" : "No"}**\n` +
        `🏷 Roles granted: **${grantedRoles.join(", ") || "None"}**\n\n` +
        `Channel will close shortly…`
      );
      setTimeout(() => channel.delete().catch(() => {}), VERIFIED_CLOSE_MS);
      createdChannels.delete(userId);
    }

    challenges.delete(userId);

    return res.json({ success: true, score, nft: isNftHolder, roles: grantedRoles });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

client.login(TOKEN);
