import fs from "node:fs/promises";
import { Sandbox } from "e2b";

const apiKey = process.env.E2B_API_KEY;
const gatewayUrl = process.env.GATEWAY_URL;
const relayKey = process.env.RELAY_ACCESS_KEY;
if (!apiKey?.startsWith("e2b_")) throw new Error("Missing E2B_API_KEY");
if (!gatewayUrl?.startsWith("https://")) throw new Error("Missing GATEWAY_URL");
if (!relayKey) throw new Error("Missing RELAY_ACCESS_KEY");

const paginator = Sandbox.list({
  apiKey,
  limit: 100,
  order: "desc",
  query: { metadata: { managedBy: "e2b-fleet-controller", fleet: "1" } },
});
const existing = await paginator.nextItems();
let created = false;
let sandbox;
if (existing.length) {
  sandbox = await Sandbox.connect(existing[0].sandboxId, { apiKey });
} else {
  created = true;
  sandbox = await Sandbox.create("ajawes-project/capacity-8-4gb-v1", {
    apiKey,
    timeoutMs: 1_200_000,
    metadata: { managedBy: "relay-canary-v2" },
  });
}

try {
  await sandbox.commands.run(
    "pkill -x node-helper 2>/dev/null || pkill -f '^node-helper ' 2>/dev/null || true",
    { timeoutMs: 10_000 },
  );
  await sandbox.files.write(
    "/tmp/runtime_agent.py",
    await fs.readFile("runtime_agent.py", "utf8"),
  );
  await sandbox.commands.run(
    [
      `GATEWAY_URL=${JSON.stringify(gatewayUrl)}`,
      `RELAY_ACCESS_KEY=${JSON.stringify(relayKey)}`,
      "ACCOUNT=Error404H",
      `WORKER=relay-${Date.now().toString(36)}`,
      "THREADS=2",
      "RUN_SECONDS=900",
      "python3 /tmp/runtime_agent.py >/tmp/runtime-agent.log 2>&1 &",
    ].join(" "),
    { timeoutMs: 10_000 },
  );
  for (let elapsed = 30; elapsed <= 900; elapsed += 30) {
    await new Promise((resolve) => setTimeout(resolve, 30_000));
    const result = await sandbox.commands.run(
      "tail -n 5 /tmp/runtime-agent.log 2>/dev/null || true",
      { timeoutMs: 10_000 },
    );
    console.log(`elapsed=${elapsed}`);
    process.stdout.write(result.stdout);
  }
} finally {
  if (created) await sandbox.kill();
}
