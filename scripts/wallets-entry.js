import { createAppKit } from "@reown/appkit";
import { EthersAdapter } from "@reown/appkit-adapter-ethers";
import { mainnet, base } from "@reown/appkit/networks";
import { initWaaP } from "@human.tech/waap-sdk";

window.__reown = { createAppKit, EthersAdapter, mainnet, base };
window.__initWaaP = initWaaP;
