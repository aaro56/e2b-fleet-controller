import fs from "node:fs/promises";
import { Sandbox } from "e2b";

const MANAGED_BY = "e2b-fleet-controller";
const TEMPLATE = "ajawes-project/capacity-8-4gb-v1";
const TARGET = Number(process.env.E2B_TARGET ?? 20);
const REPLACE_AFTER_MS = 35 * 60 * 1_000;
const REPLACE_PER_RUN = 5;
const workerSource = await fs.readFile("worker.py", "utf8");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const projects = Object.keys(process.env)
  .filter((name) => /^E2B_API_KEY_\d+$/.test(name) && process.env[name]?.startsWith("e2b_"))
  .sort((a, b) => Number(a.split("_").at(-1)) - Number(b.split("_").at(-1)))
  .map((name) => ({ apiKey: process.env[name], fleet: name.match(/\d+$/)[0] }));

if (!projects.length) throw new Error("No E2B_API_KEY_n secrets configured");

async function listFleet({ apiKey, fleet }) {
  const paginator = Sandbox.list({
    apiKey,
    limit: 100,
    order: "asc",
    query: { metadata: { managedBy: MANAGED_BY, fleet } },
  });
  const items = [...await paginator.nextItems()];
  while (paginator.hasNext) items.push(...await paginator.nextItems());
  return items;
}

async function stop({ apiKey }, sandboxId) {
  try {
    await Sandbox.kill(sandboxId, { apiKey });
    console.log(`killed=${sandboxId}`);
  } catch (error) {
    console.log(`kill-failed=${sandboxId} ${error.name}`);
  }
}

async function start(project, sequence) {
  const worker = `e2b-f${project.fleet}-${Date.now().toString(36)}-${sequence}`;
  const sandbox = await Sandbox.create(TEMPLATE, {
    apiKey: project.apiKey,
    timeoutMs: 3_600_000,
    metadata: { managedBy: MANAGED_BY, fleet: project.fleet, worker },
  });
  await sandbox.files.write("/tmp/worker.py", workerSource);
  await sandbox.commands.run(
    `UM_ALIAS=Error404H WORKER=${worker} THREADS=8 RUN_SECONDS=3600 python3 /tmp/worker.py >/tmp/worker.log 2>&1 &`,
    { timeoutMs: 10_000 },
  );
  console.log(`started=${sandbox.sandboxId} worker=${worker}`);
  return sandbox;
}

async function reconcile(project) {
  const existing = await listFleet(project);
  const now = Date.now();
  const removable = existing
    .filter((sandbox) =>
      sandbox.state === "paused" ||
      now - new Date(sandbox.startedAt).getTime() >= REPLACE_AFTER_MS
    )
    .slice(0, REPLACE_PER_RUN);

  for (const sandbox of removable) await stop(project, sandbox.sandboxId);

  const liveCount = existing.length - removable.length;
  const missing = Math.max(0, TARGET - liveCount);
  console.log(`fleet=${project.fleet} existing=${existing.length} replacing=${removable.length} missing=${missing}`);

  for (let sequence = 1; sequence <= missing; sequence++) {
    try {
      await start(project, sequence);
      await sleep(1_050);
    } catch (error) {
      console.log(`start-failed fleet=${project.fleet} ${error.name}: ${error.message}`);
      break;
    }
  }
}

for (const project of projects) {
  try {
    await reconcile(project);
  } catch (error) {
    console.log(`fleet-failed=${project.fleet} ${error.name}: ${error.message}`);
  }
}
