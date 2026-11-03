import { query, mutation } from "./_generated/server";
import { v } from "convex/values";

/* ============================================================
   חנת״ר + — פונקציות שרת (Convex)

   ריבוי כיתות:
   - "default" (הכיתה הראשית) מאומתת מול משתני הסביבה HANTAR_PIN / COMMANDER_PIN
     (Convex Dashboard ← Settings ← Environment Variables, בלי טרמינל).
   - כיתות נוספות: נוצרות מתוך האפליקציה (כפתור ניהול נסתר) ונשמרות בטבלת
     classes עם קודים כ-hash (PBKDF2+salt) בלבד. login() מוצא את הכיתה הנכונה
     לפי הקוד שהוזן, ומכאן כל קריאה מועברת עם אותו classId ומסוננת אליו בלבד —
     כך שעדכון של חנת״ר אחד מגיע אך ורק למפקד של *אותה* כיתה.
   - ניהול הכיתות (הוספה/רשימה/מחיקה) מוגן, אם הוגדר, במשתנה הסביבה ADMIN_PIN.
   ============================================================ */

type Role = "hantar" | "commander";
const DEFAULT = "default";
const ITERATIONS = 100_000;
const PIN_RE = /^\d{6,12}$/;

/* ---------- קריפטו (לקודי כיתות נוספות בלבד) ---------- */
const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b as ArrayBuffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
const rndHex = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)));
async function pbkdf2(pin: string, saltHex: string, iterations: number) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations }, key, 256));
}
function safeEq(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0;
}

/* ---------- הרשאות ---------- */
async function classById(ctx: any, classId: string) {
  const id = ctx.db.normalizeId("classes", classId);
  if (!id) return null;
  return await ctx.db.get(id);
}
// בודק שהקוד שייך לתפקיד המבוקש *בכיתה הזו בדיוק*. לא בודק כיתות אחרות.
async function checkRole(ctx: any, classId: string, role: Role, pin: string): Promise<boolean> {
  if (classId === DEFAULT) {
    const want = role === "hantar" ? process.env.HANTAR_PIN : process.env.COMMANDER_PIN;
    return !!want && safeEq(pin, want);
  }
  const c = await classById(ctx, classId);
  if (!c) return false;
  const { salt, hash } = role === "hantar" ? { salt: c.hantarSalt, hash: c.hantarHash } : { salt: c.commanderSalt, hash: c.commanderHash };
  return safeEq(await pbkdf2(pin, salt, c.iterations), hash);
}
async function need(ctx: any, classId: string, pin: string, allowed: Role[]): Promise<Role> {
  for (const r of allowed) if (await checkRole(ctx, classId, r, pin)) return r;
  throw new Error("אין הרשאה");
}
function needAdmin(adminPin: string) {
  const want = process.env.ADMIN_PIN;
  if (want && !safeEq(adminPin || "", want)) throw new Error("קוד ניהול שגוי");
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const checkDate = (d: string) => { if (!DATE.test(d)) throw new Error("תאריך לא תקין"); };
const checkTime = (t: string) => { if (!TIME.test(t)) throw new Error("שעה לא תקינה"); };
const checkClassId = (c: string) => { if (!c || c.length > 64) throw new Error("כיתה לא תקינה"); };

const markV = v.object({
  s: v.union(v.literal("P"), v.literal("A"), v.literal("L")),
  at: v.number(),
  late: v.optional(v.boolean()),
  arr: v.optional(v.number()),
  eta: v.optional(v.string()),
  note: v.optional(v.string()),
});
const evV = v.object({
  ts: v.number(), k: v.string(), date: v.optional(v.string()), sid: v.optional(v.string()), name: v.optional(v.string()),
  st: v.optional(v.string()), late: v.optional(v.boolean()), eta: v.optional(v.string()), time: v.optional(v.string()),
  orig: v.optional(v.string()), reason: v.optional(v.string()), n: v.optional(v.number()),
});

async function setSetting(ctx: any, classId: string, key: string, value: any) {
  const ex = await ctx.db.query("settings").withIndex("by_class_key", (q: any) => q.eq("classId", classId).eq("key", key)).first();
  if (ex) await ctx.db.patch(ex._id, { value }); else await ctx.db.insert("settings", { classId, key, value });
}
async function addEvent(ctx: any, classId: string, date: string, ev: any) {
  if (!ev) return;
  const { date: _d, ...rest } = ev;
  await ctx.db.insert("events", { classId, date, ...rest });
}
async function upsertMark(ctx: any, classId: string, date: string, sid: string, mark: any | null) {
  const ex = await ctx.db.query("marks").withIndex("by_class_date_sid", (q: any) => q.eq("classId", classId).eq("date", date).eq("sid", sid)).first();
  if (mark) { if (ex) await ctx.db.replace(ex._id, { classId, date, sid, ...mark }); else await ctx.db.insert("marks", { classId, date, sid, ...mark }); }
  else if (ex) await ctx.db.delete(ex._id);
}

/* ============ אימות והתחברות ============ */

// האם משתני הסביבה של הכיתה הראשית מוגדרים (לא חושף את הקודים עצמם)
export const status = query({
  args: {},
  handler: async () => ({ configured: !!process.env.HANTAR_PIN && !!process.env.COMMANDER_PIN }),
});

// מנסה קודם את הכיתה הראשית (משתני סביבה), ואז סורק כיתות נוספות. הקוד
// קובע הן את התפקיד (ע"פ הכפתור שנלחץ) והן את הכיתה — באופן חד-משמעי.
export const login = mutation({
  args: { role: v.union(v.literal("hantar"), v.literal("commander")), pin: v.string() },
  handler: async (ctx, { role, pin }) => {
    if (await checkRole(ctx, DEFAULT, role, pin)) return { ok: true as const, classId: DEFAULT, className: "" };
    for (const c of await ctx.db.query("classes").collect()) {
      if (await checkRole(ctx, c._id, role, pin)) return { ok: true as const, classId: c._id, className: c.name };
    }
    const configured = role === "hantar" ? !!process.env.HANTAR_PIN : !!process.env.COMMANDER_PIN;
    return { ok: false as const, reason: configured || (await ctx.db.query("classes").collect()).length ? "bad" as const : "unconfigured" as const };
  },
});

// שחזור התחברות קיימת: מוודא שהקוד השמור עדיין תקף *לאותה כיתה ותפקיד בדיוק*.
export const whoami = query({
  args: { classId: v.string(), pin: v.string() },
  handler: async (ctx, { classId, pin }) => {
    checkClassId(classId);
    if (await checkRole(ctx, classId, "hantar", pin)) return "hantar";
    if (await checkRole(ctx, classId, "commander", pin)) return "commander";
    return null;
  },
});

/* ============ קריאה ============ */

// תמונת מצב מלאה (reactive) — מסוננת לגמרי לפי classId. שום מסמך של כיתה
// אחרת לא עובר דרך השאילתה הזו, גם לא בעקיפין.
export const snapshot = query({
  args: { classId: v.string(), pin: v.string(), since: v.string() },
  handler: async (ctx, { classId, pin, since }) => {
    checkClassId(classId);
    await need(ctx, classId, pin, ["hantar", "commander"]);
    checkDate(since);
    const students = (await ctx.db.query("students").withIndex("by_class", (q) => q.eq("classId", classId)).collect())
      .sort((a, b) => a.order - b.order).map((s) => ({ id: s.sid, name: s.name }));
    const settings: Record<string, any> = {};
    for (const s of await ctx.db.query("settings").withIndex("by_class_key", (q) => q.eq("classId", classId)).collect()) settings[s.key] = s.value;
    const days: Record<string, any> = {};
    const day = (d: string) => (days[d] ??= { marks: {}, events: [] });
    for (const m of await ctx.db.query("marks").withIndex("by_class_date", (q) => q.eq("classId", classId).gte("date", since)).collect()) {
      const { _id, _creationTime, classId: _c, date, sid, ...mark } = m as any; day(date).marks[sid] = mark;
    }
    for (const c of await ctx.db.query("closes").withIndex("by_class_date", (q) => q.eq("classId", classId).gte("date", since)).collect()) {
      const { _id, _creationTime, classId: _c, date, ...close } = c as any; day(date).close = close;
    }
    for (const c of await ctx.db.query("cancellations").withIndex("by_class_date", (q) => q.eq("classId", classId).gte("date", since)).collect()) {
      const { _id, _creationTime, classId: _c, date, ...cancelled } = c as any; day(date).cancelled = cancelled;
    }
    for (const e of await ctx.db.query("events").withIndex("by_class_date", (q) => q.eq("classId", classId).gte("date", since)).collect()) {
      const { _id, _creationTime, classId: _c, ...ev } = e as any; day(e.date).events.push(ev);
    }
    for (const d of Object.values(days)) (d as any).events.sort((a: any, b: any) => a.ts - b.ts);
    return { className: classId === DEFAULT ? "" : (await classById(ctx, classId))?.name ?? "", students, config: { schedule: settings.schedule ?? null, demo: !!settings.demo }, meta: { cmd: settings.cmd ?? null }, days };
  },
});

/* ============ כתיבה: חנת״ר ============ */

export const mark = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), sid: v.string(), mark: v.union(markV, v.null()), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    checkClassId(a.classId); await need(ctx, a.classId, a.pin, ["hantar"]); checkDate(a.date);
    await upsertMark(ctx, a.classId, a.date, a.sid, a.mark);
    await addEvent(ctx, a.classId, a.date, a.ev);
  },
});

export const markMany = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), entries: v.array(v.object({ sid: v.string(), mark: v.union(markV, v.null()) })), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    checkClassId(a.classId); await need(ctx, a.classId, a.pin, ["hantar"]); checkDate(a.date);
    if (a.entries.length > 500) throw new Error("יותר מדי רשומות");
    for (const e of a.entries) await upsertMark(ctx, a.classId, a.date, e.sid, e.mark);
    await addEvent(ctx, a.classId, a.date, a.ev);
  },
});

export const setStudents = mutation({
  args: { classId: v.string(), pin: v.string(), list: v.array(v.object({ id: v.string(), name: v.string() })) },
  handler: async (ctx, { classId, pin, list }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["hantar"]);
    if (list.length > 500) throw new Error("יותר מדי תלמידים");
    const existing = await ctx.db.query("students").withIndex("by_class", (q) => q.eq("classId", classId)).collect();
    const bySid = new Map(existing.map((s) => [s.sid, s]));
    const keep = new Set<string>();
    for (let i = 0; i < list.length; i++) {
      const name = list[i].name.trim().slice(0, 80); if (!name) continue; keep.add(list[i].id);
      const ex = bySid.get(list[i].id);
      if (ex) await ctx.db.patch(ex._id, { name, order: i }); else await ctx.db.insert("students", { classId, sid: list[i].id, name, order: i });
    }
    for (const s of existing) if (!keep.has(s.sid)) await ctx.db.delete(s._id);
  },
});

export const setSchedule = mutation({
  args: { classId: v.string(), pin: v.string(), schedule: v.any() },
  handler: async (ctx, { classId, pin, schedule }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["hantar"]);
    const out: Record<string, string> = {};
    for (let d = 0; d <= 4; d++) { const t = String(schedule?.[d] ?? ""); if (t) checkTime(t); out[String(d)] = t; } // ראשון-חמישי בלבד
    await setSetting(ctx, classId, "schedule", out);
  },
});

export const setDemo = mutation({
  args: { classId: v.string(), pin: v.string(), on: v.boolean() },
  handler: async (ctx, { classId, pin, on }) => { checkClassId(classId); await need(ctx, classId, pin, ["hantar"]); await setSetting(ctx, classId, "demo", on); },
});

// עדכון שעת מסדר סיום — מאפס אישור קבלה קודם (המפקד צריך לאשר מחדש)
export const setClose = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), close: v.object({ time: v.string(), orig: v.string(), reason: v.optional(v.string()), note: v.optional(v.string()), at: v.number() }), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    checkClassId(a.classId); await need(ctx, a.classId, a.pin, ["hantar"]); checkDate(a.date); checkTime(a.close.time);
    const ex = await ctx.db.query("closes").withIndex("by_class_date", (q) => q.eq("classId", a.classId).eq("date", a.date)).first();
    if (ex) await ctx.db.replace(ex._id, { classId: a.classId, date: a.date, ...a.close }); else await ctx.db.insert("closes", { classId: a.classId, date: a.date, ...a.close });
    await addEvent(ctx, a.classId, a.date, a.ev);
  },
});

// טעינת מצב שלם (נתוני הדגמה / ייבוא) — מוחק את נתוני המסדר *של הכיתה הזו בלבד* ומחליף
export const importState = mutation({
  args: { classId: v.string(), pin: v.string(), state: v.any() },
  handler: async (ctx, { classId, pin, state }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["hantar"]);
    const idx: Record<string, string> = { students: "by_class", settings: "by_class_key", marks: "by_class_date", closes: "by_class_date", cancellations: "by_class_date", events: "by_class_date" };
    for (const t of ["students", "settings", "marks", "closes", "cancellations", "events"] as const)
      for (const d of await ctx.db.query(t).withIndex(idx[t] as any, (q: any) => q.eq("classId", classId)).collect()) await ctx.db.delete(d._id);
    const students: { id: string; name: string }[] = state?.students ?? [];
    for (let i = 0; i < students.length; i++) await ctx.db.insert("students", { classId, sid: students[i].id, name: String(students[i].name).slice(0, 80), order: i });
    const sch = state?.config?.schedule; if (sch) await setSetting(ctx, classId, "schedule", sch);
    await setSetting(ctx, classId, "demo", !!state?.config?.demo);
    for (const [date, day] of Object.entries<any>(state?.days ?? {})) {
      checkDate(date);
      for (const [sid, m] of Object.entries<any>(day.marks ?? {})) await ctx.db.insert("marks", { classId, date, sid, ...m });
      if (day.close) await ctx.db.insert("closes", { classId, date, ...day.close });
      if (day.cancelled) await ctx.db.insert("cancellations", { classId, date, ...day.cancelled });
      for (const e of day.events ?? []) { const { date: _d, ...rest } = e; await ctx.db.insert("events", { classId, date, ...rest }); }
    }
  },
});

/* ============ כתיבה: מפקד ============ */

export const ack = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), ts: v.number() },
  handler: async (ctx, { classId, pin, date, ts }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["commander"]); checkDate(date);
    const c = await ctx.db.query("closes").withIndex("by_class_date", (q) => q.eq("classId", classId).eq("date", date)).first();
    if (!c) return;
    await ctx.db.patch(c._id, { ackAt: ts });
    await ctx.db.insert("events", { classId, date, ts, k: "ack", time: c.time });
  },
});

export const cmdEnter = mutation({
  args: { classId: v.string(), pin: v.string(), ts: v.number(), prev: v.optional(v.union(v.number(), v.null())) },
  handler: async (ctx, { classId, pin, ts, prev }) => { checkClassId(classId); await need(ctx, classId, pin, ["commander"]); await setSetting(ctx, classId, "cmd", { enteredAt: ts, prev: prev ?? null }); },
});

// הודעת מפקד על ביטול המסדר (או ביטול ההודעה) ליום מסוים
export const setCancelled = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), cancelled: v.boolean(), reason: v.optional(v.string()), note: v.optional(v.string()) },
  handler: async (ctx, { classId, pin, date, cancelled, reason, note }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["commander"]); checkDate(date);
    const ex = await ctx.db.query("cancellations").withIndex("by_class_date", (q) => q.eq("classId", classId).eq("date", date)).first();
    if (!cancelled) { if (ex) await ctx.db.delete(ex._id); await ctx.db.insert("events", { classId, date, ts: Date.now(), k: "uncancel" }); return; }
    const doc = { classId, date, reason, note, at: Date.now() };
    if (ex) await ctx.db.replace(ex._id, doc); else await ctx.db.insert("cancellations", doc);
    await ctx.db.insert("events", { classId, date, ts: Date.now(), k: "cancel", reason });
  },
});

/* ============ ניהול כיתות (כפתור נסתר) ============ */
// מוגן ב-ADMIN_PIN אם הוגדר (Convex Dashboard ← Environment Variables). אם לא
// הוגדר, הפונקציות האלו פתוחות לכל מי שמגיע לכפתור הנסתר — זה תחליף סביר
// להגנה אמיתית, לא תחליף לה; מומלץ להגדיר ADMIN_PIN.

export const listClasses = query({
  args: { adminPin: v.string() },
  handler: async (ctx, { adminPin }) => {
    needAdmin(adminPin);
    return (await ctx.db.query("classes").collect()).sort((a, b) => b.createdAt - a.createdAt).map((c) => ({ classId: c._id, name: c.name, createdAt: c.createdAt }));
  },
});

export const addClass = mutation({
  args: { adminPin: v.string(), name: v.string(), hantarPin: v.string(), commanderPin: v.string() },
  handler: async (ctx, { adminPin, name, hantarPin, commanderPin }) => {
    needAdmin(adminPin);
    const nm = name.trim().slice(0, 60); if (!nm) throw new Error("שם הכיתה חסר");
    if (!PIN_RE.test(hantarPin) || !PIN_RE.test(commanderPin)) throw new Error("הקוד חייב להכיל 6 עד 12 ספרות");
    if (hantarPin === commanderPin) throw new Error("קוד החנת״ר וקוד המפקד חייבים להיות שונים");
    if (await checkRole(ctx, DEFAULT, "hantar", hantarPin) || await checkRole(ctx, DEFAULT, "commander", commanderPin))
      throw new Error("אחד הקודים כבר בשימוש בכיתה הראשית");
    for (const c of await ctx.db.query("classes").collect()) {
      if (await pbkdf2(hantarPin, c.hantarSalt, c.iterations) === c.hantarHash || await pbkdf2(hantarPin, c.commanderSalt, c.iterations) === c.commanderHash)
        throw new Error("קוד החנת״ר כבר בשימוש בכיתה אחרת");
      if (await pbkdf2(commanderPin, c.hantarSalt, c.iterations) === c.hantarHash || await pbkdf2(commanderPin, c.commanderSalt, c.iterations) === c.commanderHash)
        throw new Error("קוד המפקד כבר בשימוש בכיתה אחרת");
    }
    const hSalt = rndHex(16), cSalt = rndHex(16);
    const classId = await ctx.db.insert("classes", {
      name: nm, iterations: ITERATIONS, createdAt: Date.now(),
      hantarSalt: hSalt, hantarHash: await pbkdf2(hantarPin, hSalt, ITERATIONS),
      commanderSalt: cSalt, commanderHash: await pbkdf2(commanderPin, cSalt, ITERATIONS),
    });
    return { classId };
  },
});

// מוחקת כיתה וכל הנתונים ששייכים לה (מדורג, בלי להשאיר יתומים)
export const removeClass = mutation({
  args: { adminPin: v.string(), classId: v.string() },
  handler: async (ctx, { adminPin, classId }) => {
    needAdmin(adminPin); checkClassId(classId);
    if (classId === DEFAULT) throw new Error("לא ניתן למחוק את הכיתה הראשית");
    const c = await classById(ctx, classId); if (!c) return;
    for (const s of await ctx.db.query("students").withIndex("by_class", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(s._id);
    for (const s of await ctx.db.query("settings").withIndex("by_class_key", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(s._id);
    for (const t of ["marks", "closes", "cancellations", "events"] as const)
      for (const d of await ctx.db.query(t).withIndex("by_class_date", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(d._id);
    await ctx.db.delete(c._id);
  },
});
