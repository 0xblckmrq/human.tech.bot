const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

(async () => {
  const outdir = path.join(__dirname, "..", "public", "vendor");
  fs.mkdirSync(outdir, { recursive: true });

  await esbuild.build({
    entryPoints: [path.join(__dirname, "wallets.entry.js")],
    bundle: true,
    minify: true,
    format: "iife",
    globalName: "WalletBundles",
    platform: "browser",
    target: ["es2020"],
    outfile: path.join(outdir, "wallets.bundle.js"),

    // @human.tech/waap-sdk imports react as a peer dependency; exclude it from the bundle.
    external: ["react", "react-dom"],
  });

  console.log("✅ Built public/vendor/wallets.bundle.js");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
