import { Hono } from "hono";
import { serveStatic } from "hono/cloudflare-workers";
import { getCookie, setCookie } from "hono/cookie";
import { v4 as uuidv4 } from "uuid";

import manifest from "__STATIC_CONTENT_MANIFEST";
import { Bindings } from "./bindings";
import {
  getAuthenticationOptions,
  getRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
} from "./auth";

const app = new Hono<{ Bindings: Bindings }>();

app.get("/*", serveStatic({ root: "./public/", manifest }));

app.get("/attestation/options", async (c) => {
  try {
    const { userName } = c.req.query();
    const options = await getRegistrationOptions(userName, c.env);
    return c.json({ status: "success", options });
  } catch (e: any) {
    return c.json({ status: "error", error: e.toString() }, 500);
  }
});

app.post("/attestation/result", async (c) => {
  try {
    const { userName, body } = await c.req.json();
    await verifyRegistration(userName, body, c.env);
    return c.json({ verified: true });
  } catch (e: any) {
    return c.json({ verified: false, error: e.toString() }, 500);
  }
});

app.get("/assertion/options", async (c) => {
  try {
    const { userName } = c.req.query();
    const options = await getAuthenticationOptions(userName, c.env);
    return c.json({ status: "success", options });
  } catch (e: any) {
    return c.json({ status: "error", error: e.toString() }, 500);
  }
});

app.post("/assertion/result", async (c) => {
  try {
    const { userName, body } = await c.req.json();
    const verified = await verifyAuthentication(userName, body, c.env);

    // セッションを発行
    if (verified) {
      const ttl = 60 * 60 * 24;
      const sessionId = uuidv4();
      setCookie(c, "session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: ttl,
        path: "/",
      });
      await c.env.KV.put(`session/${sessionId}`, userName, {
        expirationTtl: ttl,
      });
    }

    return c.json({ verified }, 500);
  } catch (e: any) {
    return c.json({ verified: false, error: e.toString() }, 500);
  }
});

app.get("/restricted", async (c) => {
  const sessionId = getCookie(c, "session_id");
  if (!sessionId) {
    return c.text("Unauthorized", 401);
  }
  const userName = await c.env.KV.get(`session/${sessionId}`);
  if (!userName) {
    return c.text("Unauthorized", 401);
  }
  return c.text(`Welcome, ${userName}!`);
});

export default app;
