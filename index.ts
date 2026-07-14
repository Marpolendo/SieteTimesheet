// ============================================================
// SIETE Crew Ledger — admin-only user provisioning
// Deploy:  supabase functions deploy create-crew-member
// Secrets: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
//          are injected automatically by Supabase.
//
// Actions:
//   create      → make a new crew auth user + profile row
//   setpin      → reset a member's PIN
// Both require the CALLER to be an admin (verified from their JWT).
// ============================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const EMAIL_DOMAIN = "crew.siete.local";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // --- verify the caller is a signed-in admin ---
  const authHeader = req.headers.get("Authorization") ?? "";
  const asCaller = createClient(url, anon, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: userData, error: userErr } = await asCaller.auth.getUser();
  if (userErr || !userData?.user) return json({ error: "Not signed in" }, 401);

  const admin = createClient(url, service);
  const { data: me } = await admin
    .from("profiles")
    .select("role, active")
    .eq("id", userData.user.id)
    .single();
  if (!me || me.role !== "admin" || !me.active)
    return json({ error: "Admins only" }, 403);

  // --- parse ---
  let body: Record<string, any>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Bad JSON" }, 400);
  }
  const action = body.action ?? "create";

  const validPin = (p: unknown) => typeof p === "string" && /^\d{4,8}$/.test(p);
  const validUser = (u: unknown) => typeof u === "string" && /^[a-z0-9._-]{2,32}$/.test(u);

  // ---------- reset PIN ----------
  if (action === "setpin") {
    if (!body.id || !validPin(body.pin))
      return json({ error: "Need id and a 4–8 digit pin" }, 400);
    const { error } = await admin.auth.admin.updateUserById(body.id, {
      password: body.pin,
    });
    if (error) return json({ error: error.message }, 400);
    return json({ ok: true });
  }

  // ---------- create crew member ----------
  if (action === "create") {
    const { username, display_name, pin, pay_type, rate, salary_per_period, tax_pct } = body;
    if (!validUser(username)) return json({ error: "Username: 2–32 chars, a–z 0–9 . _ -" }, 400);
    if (!display_name?.trim()) return json({ error: "Display name required" }, 400);
    if (!validPin(pin)) return json({ error: "PIN must be 4–8 digits" }, 400);

    const email = `${username}@${EMAIL_DOMAIN}`;

    const { data: created, error: cErr } = await admin.auth.admin.createUser({
      email,
      password: pin,
      email_confirm: true,
    });
    if (cErr) return json({ error: cErr.message }, 400);

    const { error: pErr } = await admin.from("profiles").insert({
      id: created.user.id,
      username,
      display_name: display_name.trim(),
      role: "employee",
      pay_type: pay_type === "salary" ? "salary" : "hourly",
      rate: Number(rate) || 0,
      salary_per_period: Number(salary_per_period) || 0,
      tax_pct: Number(tax_pct) || 0,
    });
    if (pErr) {
      // roll back the orphaned auth user so username stays free
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: pErr.message }, 400);
    }
    return json({ ok: true, id: created.user.id });
  }

  return json({ error: "Unknown action" }, 400);
});
