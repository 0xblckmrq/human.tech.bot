# human.tech Covenant Verification Bot

A Discord bot that links a user’s **Ethereum wallet** to their **Discord account** and automatically manages roles based on covenant status, NFT ownership, and Humanity Passport scores.

Once a wallet is verified **one time**, roles are **kept in sync automatically** — including removal when NFTs are sold.

---

## ✨ Key Features

- One-time wallet verification (cryptographic signature)
- Automatic role assignment & removal
- NFT sell detection → role revocation
- No repeated signing required
- Private verification channels
- Status dashboard (signer page)
- User-controlled wallet changes
- Production-safe, extensible architecture

---

## 🧠 How It Works

1. User runs `/verify` in Discord  
2. Bot opens a private verification channel  
3. User signs a challenge with their wallet  
4. Bot links Discord ID ↔ Wallet Address  
5. Roles are assigned  
6. Roles update automatically forever after

---

## 🎭 Roles & Eligibility

### Covenant Roles
- **Covenant Verified Signatory**
  - Wallet is SIGNED + VERIFIED in the covenant manifest
- **Covenant Signatory O.G.**
  - Wallet owns an approved Covenant NFT

Both unlock covenant discussion and meme contest channels.

### Humanity Passport Roles
- **O.G. HUMN**
- **Chosen One**

Assigned based on Humanity Passport score thresholds.

---

## 🔁 Automatic Role Management

- Detects NFT transfers and revokes roles if eligibility is lost
- Restores roles automatically if eligibility returns
- Includes scheduled refresh as a safety net

No user action required.

---

## 🖥 Signer Page

- Shows linked wallet
- Displays role status and reasons
- No signing required after first verification
- Users can change wallet by signing again

---

## 🏗 Architecture

**Bot**
- Node.js
- discord.js v14
- ethers.js
- Express

Handles:
- Slash commands
- Signature verification
- Role logic
- Wallet persistence
- NFT checks
- API endpoints

**Signer**
- Static HTML served by Express
- Wallet connect + signing
- Status-only mode

---

## 📦 Deployment

### Hosting
Render Web Service (always-on)

### Required Environment Variables
```
BOT_TOKEN
CLIENT_ID
GUILD_ID
WHITELIST_API_KEY
PASSPORT_API_KEY
ALCHEMY_BASE_KEY
```

### Recommended
```
ROLE_REFRESH_MINUTES=1440
ALCHEMY_ETH_KEY
ALCHEMY_WEBHOOK_SIGNING_KEY
```

---

## 🔐 Safety & Privacy

- Private channels
- No fund transfers
- No public signatures
- Auto channel deletion
- Wallet changes are user-controlled

---

## ⚠️ Limitations

- One wallet per user
- Wallet change requires re-signing
- Mobile requires wallet-enabled browsers
- Ephemeral storage resets mappings on redeploy

---

## 📜 License

MIT
