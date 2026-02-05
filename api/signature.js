import { ethers } from "ethers";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const { userId, signature } = req.body || {};
    if (!userId || !signature) return res.status(400).json({ error: "Missing userId or signature" });

    // IMPORTANT:
    // Vercel has no access to your bot's in-memory `challenges` Map.
    // So you must move challenge storage somewhere shared:
    // - Redis (Upstash)
    // - a DB
    // - or a signed JWT challenge approach

    return res.status(501).json({
      error: "Not wired yet: need shared challenge storage between bot and Vercel."
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || String(e) });
  }
}

