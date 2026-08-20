import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

function cookieFrom(response) {
  return response.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
}

test("setup, CSRF protection, encrypted dashboard and logout", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "cybertarcza-api-"));
  const port = 31_000 + Math.floor(Math.random() * 2_000);
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, [join(process.cwd(), "secure-app", "server.mjs")], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", APP_ORIGIN: origin, COOKIE_SECURE: "0", DISABLE_EXTERNAL_CHECKS: "1", DATA_FILE: join(directory, "vault.json") },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("server_start_timeout")), 10_000);
      child.stdout.on("data", (chunk) => {
        if (chunk.toString().includes("CyberTarcza listening")) { clearTimeout(timer); resolve(); }
      });
      child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`server_exited_${code}`)); });
    });

    const status = await fetch(`${origin}/api/status`);
    assert.equal(status.status, 200);
    assert.equal((await status.json()).initialized, false);

    const password = "bezpieczne testowe haslo glowne sklada sie z wielu slow";
    const setup = await fetch(`${origin}/api/setup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password, confirmation: password }),
    });
    assert.equal(setup.status, 201);
    const setupData = await setup.json();
    const cookie = cookieFrom(setup);
    assert.ok(cookie.startsWith("ct_session="));
    assert.ok(setupData.csrf);

    const blocked = await fetch(`${origin}/api/controls`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin },
      body: JSON.stringify({ id: "account-passkeys", completed: true }),
    });
    assert.equal(blocked.status, 403);

    const changed = await fetch(`${origin}/api/controls`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin, "x-csrf-token": setupData.csrf },
      body: JSON.stringify({ id: "account-passkeys", completed: true }),
    });
    assert.equal(changed.status, 200);

    const dashboard = await fetch(`${origin}/api/dashboard`, { headers: { cookie } });
    assert.equal(dashboard.status, 200);
    const dashboardData = await dashboard.json();
    assert.ok(dashboardData.vault.completedControls.includes("account-passkeys"));
    assert.ok(dashboardData.score > 0);

    const logout = await fetch(`${origin}/api/logout`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, origin, "x-csrf-token": setupData.csrf },
      body: "{}",
    });
    assert.equal(logout.status, 200);
    const after = await fetch(`${origin}/api/dashboard`, { headers: { cookie } });
    assert.equal(after.status, 401);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
