import { query, mutation } from "./_generated/server";
import { v } from "convex/values";

/* ============================================================
   חנת״ר + — פונקציות שרת (Convex)

   תפקידים ואימות:
   - "default" (הכיתה הראשית): HANTAR_PIN / COMMANDER_PIN — משתני סביבה
     (Convex Dashboard ← Settings ← Environment Variables, בלי טרמינל).
   - כיתות נוספות: נוצרות ומנוהלות ע"י מפקד בית הספר (PRINCIPAL_PIN — גם הוא
     משתנה סביבה). לכל כיתה קוד חנת״ר וקוד מפקד קבועים, מאוחסנים כ-hash
     (PBKDF2+salt) בלבד.
   - לכל כיתה (כולל הראשית) יש גם "קוד אישי" אופציונלי למפקד: קוד נוסף,
     שהמפקד עצמו קובע/מחליף מתוך המסך שלו (setMyCommanderPin). הקוד הקבוע
     ממשיך לעבוד תמיד כגיבוי/שחזור; הקוד האישי הוא דרך כניסה *נוספת*, לא
     תחליף. מפקד בית הספר יכול לאפס קוד אישי שנשכח (resetCommanderSelfPin).
   - מפקד בית הספר הוא "האדמין": מורשה להוסיף/לשנות שם/למחוק כיתות, ולקבוע
     מחדש את הקודים הקבועים של כל כיתה. אין הפרדה בין "צפייה" ל"ניהול" —
     אותו קוד (PRINCIPAL_PIN) עושה את שניהם, משני טאבים שונים באותו מסך.
   - בדיקת ייחודיות: כל קוד חדש (קבוע או אישי) נבדק מול *כל* הקודים הקיימים
     בכל הכיתות (קבועים ואישיים כאחד) כדי שלעולם לא יהיה מצב שבו שני קודים
     זהים מנתבים לשתי כיתות שונות.
   ============================================================ */

type Role = "hantar" | "commander";
const DEFAULT = "default";
const ITERATIONS = 100_000;
const PIN_RE = /^\d{6,12}$/;

/* ---------- קריפטו ---------- */
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
type PinRec = { salt: string; hash: string; iterations: number };
const mkPin = async (pin: string) => { const salt = rndHex(16); return { salt, hash: await pbkdf2(pin, salt, ITERATIONS), iterations: ITERATIONS } as PinRec; };
const pinMatches = async (pin: string, rec: PinRec | null | undefined) => !!rec && safeEq(await pbkdf2(pin, rec.salt, rec.iterations), rec.hash);

/* ---------- הגדרות (settings) ---------- */
async function getSetting(ctx: any, classId: string, key: string) {
  const s = await ctx.db.query("settings").withIndex("by_class_key", (q: any) => q.eq("classId", classId).eq("key", key)).first();
  return s ? s.value : null;
}
async function setSetting(ctx: any, classId: string, key: string, value: any) {
  const ex = await ctx.db.query("settings").withIndex("by_class_key", (q: any) => q.eq("classId", classId).eq("key", key)).first();
  if (ex) await ctx.db.patch(ex._id, { value }); else await ctx.db.insert("settings", { classId, key, value });
}
async function delSetting(ctx: any, classId: string, key: string) {
  const ex = await ctx.db.query("settings").withIndex("by_class_key", (q: any) => q.eq("classId", classId).eq("key", key)).first();
  if (ex) await ctx.db.delete(ex._id);
}

/* ---------- הרשאות ---------- */
async function classById(ctx: any, classId: string) {
  const id = ctx.db.normalizeId("classes", classId);
  if (!id) return null;
  return await ctx.db.get(id);
}
async function fixedRec(ctx: any, classId: string, role: Role): Promise<PinRec | null> {
  if (classId === DEFAULT) return null; // env-based, checked separately
  const c = await classById(ctx, classId); if (!c) return null;
  return role === "hantar" ? { salt: c.hantarSalt, hash: c.hantarHash, iterations: c.iterations } : { salt: c.commanderSalt, hash: c.commanderHash, iterations: c.iterations };
}
async function checkRole(ctx: any, classId: string, role: Role, pin: string): Promise<boolean> {
  if (classId === DEFAULT) {
    if (role === "hantar") { const want = process.env.HANTAR_PIN; return !!want && safeEq(pin, want); }
    const want = process.env.COMMANDER_PIN;
    if (want && safeEq(pin, want)) return true;
    return pinMatches(pin, await getSetting(ctx, classId, "commanderPin2"));
  }
  if (role === "hantar") return pinMatches(pin, await fixedRec(ctx, classId, "hantar"));
  if (await pinMatches(pin, await fixedRec(ctx, classId, "commander"))) return true;
  return pinMatches(pin, await getSetting(ctx, classId, "commanderPin2"));
}
async function need(ctx: any, classId: string, pin: string, allowed: Role[]): Promise<Role> {
  for (const r of allowed) if (await checkRole(ctx, classId, r, pin)) return r;
  throw new Error("אין הרשאה");
}
function needPrincipal(pin: string) {
  const want = process.env.PRINCIPAL_PIN;
  if (!want || !safeEq(pin || "", want)) throw new Error("אין הרשאה");
}

// בודק שקוד נתון אינו בשימוש באף כיתה, באף תפקיד ובאף "שכבה" (קבוע/אישי) —
// מונע מצב שבו שני קודים זהים עלולים לנתב לשתי כיתות (או שני תפקידים) שונים.
// exclude מדלג על *שדה אחד בדיוק* (כיתה+תפקיד ספציפיים) כדי לאפשר "להשאיר אותו
// קוד" כשמעדכנים — אבל עדיין בודק את שאר השדות של *אותה כיתה עצמה* (קריטי: לא
// לדלג על הכיתה כולה, אחרת קוד אישי של מפקד יכול להתנגש בשקט עם קוד החנת״ר
// הקבוע של אותה כיתה בדיוק).
async function pinInUse(ctx: any, pin: string, exclude?: { classId: string; field: "hantar" | "commander" | "self" }): Promise<boolean> {
  const skip = (classId: string, field: string) => !!exclude && exclude.classId === classId && exclude.field === field;
  if (!skip(DEFAULT, "hantar") && process.env.HANTAR_PIN && safeEq(pin, process.env.HANTAR_PIN)) return true;
  if (!skip(DEFAULT, "commander") && process.env.COMMANDER_PIN && safeEq(pin, process.env.COMMANDER_PIN)) return true;
  if (!skip(DEFAULT, "self") && (await pinMatches(pin, await getSetting(ctx, DEFAULT, "commanderPin2")))) return true;
  for (const c of await ctx.db.query("classes").collect()) {
    if (!skip(c._id, "hantar") && (await pinMatches(pin, { salt: c.hantarSalt, hash: c.hantarHash, iterations: c.iterations }))) return true;
    if (!skip(c._id, "commander") && (await pinMatches(pin, { salt: c.commanderSalt, hash: c.commanderHash, iterations: c.iterations }))) return true;
    if (!skip(c._id, "self") && (await pinMatches(pin, await getSetting(ctx, c._id, "commanderPin2")))) return true;
  }
  return false;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const checkDate = (d: string) => { if (!DATE.test(d)) throw new Error("תאריך לא תקין"); };
const checkTime = (t: string) => { if (!TIME.test(t)) throw new Error("שעה לא תקינה"); };
const checkClassId = (c: string) => { if (!c || c.length > 64) throw new Error("כיתה לא תקינה"); };
const checkPin = (p: string, label: string) => { if (!PIN_RE.test(p)) throw new Error(`קוד ${label} חייב להכיל 6 עד 12 ספרות`); };

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

export const status = query({
  args: {},
  handler: async () => ({ configured: !!process.env.HANTAR_PIN && !!process.env.COMMANDER_PIN }),
});
export const schoolStatus = query({
  args: {},
  handler: async () => ({ configured: !!process.env.PRINCIPAL_PIN }),
});
export const principalLogin = query({
  args: { pin: v.string() },
  handler: async (_ctx, { pin }) => !!process.env.PRINCIPAL_PIN && safeEq(pin, process.env.PRINCIPAL_PIN),
});

// מנסה קודם את הכיתה הראשית, ואז סורק כיתות נוספות (קוד קבוע ואישי כאחד).
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
    return {
      className: classId === DEFAULT ? "" : (await classById(ctx, classId))?.name ?? "",
      students, config: { schedule: settings.schedule ?? null, demo: !!settings.demo, hantarStudent: settings.hantarStudent ?? null },
      meta: { cmd: settings.cmd ?? null }, hasOwnCommanderPin: !!settings.commanderPin2, days,
    };
  },
});

/* ============ כתיבה: חנת״ר ============ */

export const mark = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), sid: v.string(), mark: v.union(markV, v.null()), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => { checkClassId(a.classId); await need(ctx, a.classId, a.pin, ["hantar"]); checkDate(a.date); await upsertMark(ctx, a.classId, a.date, a.sid, a.mark); await addEvent(ctx, a.classId, a.date, a.ev); },
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
    const curHantar = await getSetting(ctx, classId, "hantarStudent");
    if (curHantar && !keep.has(curHantar)) await delSetting(ctx, classId, "hantarStudent"); // תלמיד שהוסר מפסיק להיות "החנת״ר התורן"
  },
});

// קביעת/ביטול התלמיד שמוצג כ"חנת״ר התורן" של הכיתה (שם בירוק בכל מקום)
export const setHantarStudent = mutation({
  args: { classId: v.string(), pin: v.string(), sid: v.union(v.string(), v.null()) },
  handler: async (ctx, { classId, pin, sid }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["hantar"]);
    if (sid) {
      const ex = await ctx.db.query("students").withIndex("by_class_sid", (q) => q.eq("classId", classId).eq("sid", sid)).first();
      if (!ex) throw new Error("תלמיד לא נמצא");
      await setSetting(ctx, classId, "hantarStudent", sid);
    } else await delSetting(ctx, classId, "hantarStudent");
  },
});

export const setSchedule = mutation({
  args: { classId: v.string(), pin: v.string(), schedule: v.any() },
  handler: async (ctx, { classId, pin, schedule }) => {
    checkClassId(classId); await need(ctx, classId, pin, ["hantar"]);
    const out: Record<string, string> = {};
    for (let d = 0; d <= 4; d++) { const t = String(schedule?.[d] ?? ""); if (t) checkTime(t); out[String(d)] = t; }
    await setSetting(ctx, classId, "schedule", out);
  },
});
export const setDemo = mutation({
  args: { classId: v.string(), pin: v.string(), on: v.boolean() },
  handler: async (ctx, { classId, pin, on }) => { checkClassId(classId); await need(ctx, classId, pin, ["hantar"]); await setSetting(ctx, classId, "demo", on); },
});
export const setClose = mutation({
  args: { classId: v.string(), pin: v.string(), date: v.string(), close: v.object({ time: v.string(), orig: v.string(), reason: v.optional(v.string()), note: v.optional(v.string()), at: v.number() }), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    checkClassId(a.classId); await need(ctx, a.classId, a.pin, ["hantar"]); checkDate(a.date); checkTime(a.close.time);
    const ex = await ctx.db.query("closes").withIndex("by_class_date", (q) => q.eq("classId", a.classId).eq("date", a.date)).first();
    if (ex) await ctx.db.replace(ex._id, { classId: a.classId, date: a.date, ...a.close }); else await ctx.db.insert("closes", { classId: a.classId, date: a.date, ...a.close });
    await addEvent(ctx, a.classId, a.date, a.ev);
  },
});

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

// המפקד קובע/מחליף קוד אישי משלו (דרך כניסה נוספת; הקוד הקבוע ממשיך לעבוד
// תמיד). כדי לקבוע קוד אישי צריך כבר להיות מחובר כמפקד (עם קוד כלשהו שעובד).
export const setMyCommanderPin = mutation({
  args: { classId: v.string(), pin: v.string(), newPin: v.string() },
  handler: async (ctx, { classId, pin, newPin }) => {
    checkClassId(classId);
    if (!(await checkRole(ctx, classId, "commander", pin))) throw new Error("אין הרשאה");
    checkPin(newPin, "אישי");
    if (await pinInUse(ctx, newPin, { classId, field: "self" })) throw new Error("הקוד הזה כבר בשימוש");
    await setSetting(ctx, classId, "commanderPin2", await mkPin(newPin));
  },
});

/* ============ מפקד בית הספר: צפייה וניהול (אותו קוד, שני טאבים) ============ */

export const schoolSnapshot = query({
  args: { pin: v.string(), date: v.string() },
  handler: async (ctx, { pin, date }) => {
    needPrincipal(pin); checkDate(date);
    const build = async (classId: string, name: string) => {
      const students = (await ctx.db.query("students").withIndex("by_class", (q) => q.eq("classId", classId)).collect())
        .sort((a, b) => a.order - b.order).map((s) => ({ id: s.sid, name: s.name }));
      const marks: Record<string, any> = {};
      for (const m of await ctx.db.query("marks").withIndex("by_class_date", (q) => q.eq("classId", classId).eq("date", date)).collect()) {
        const { s, late, at, arr, eta } = m as any; marks[m.sid] = { s, late, at, arr, eta };
      }
      const close = await ctx.db.query("closes").withIndex("by_class_date", (q) => q.eq("classId", classId).eq("date", date)).first();
      const cancelled = await ctx.db.query("cancellations").withIndex("by_class_date", (q) => q.eq("classId", classId).eq("date", date)).first();
      const hantarStudent = await getSetting(ctx, classId, "hantarStudent");
      return { classId, name, students, marks, close: close ? { time: close.time, orig: close.orig } : null, cancelled: cancelled ? { reason: cancelled.reason ?? null } : null, hantarStudent };
    };
    const classes = [await build(DEFAULT, "")];
    for (const c of await ctx.db.query("classes").collect()) classes.push(await build(c._id, c.name));
    return { date, classes };
  },
});

export const listClasses = query({
  args: { pin: v.string() },
  handler: async (ctx, { pin }) => {
    needPrincipal(pin);
    const rows = [{ classId: DEFAULT, name: "כיתה ראשית", createdAt: 0, fixed: false, hasOwnCommanderPin: !!(await getSetting(ctx, DEFAULT, "commanderPin2")) }];
    for (const c of await ctx.db.query("classes").collect())
      rows.push({ classId: c._id, name: c.name, createdAt: c.createdAt, fixed: true, hasOwnCommanderPin: !!(await getSetting(ctx, c._id, "commanderPin2")) });
    return rows.sort((a, b) => a.createdAt - b.createdAt);
  },
});

export const addClass = mutation({
  args: { pin: v.string(), name: v.string(), hantarPin: v.string(), commanderPin: v.string() },
  handler: async (ctx, { pin, name, hantarPin, commanderPin }) => {
    needPrincipal(pin);
    const nm = name.trim().slice(0, 60); if (!nm) throw new Error("שם הכיתה חסר");
    checkPin(hantarPin, "חנת״ר"); checkPin(commanderPin, "מפקד");
    if (hantarPin === commanderPin) throw new Error("קוד החנת״ר וקוד המפקד חייבים להיות שונים");
    if (await pinInUse(ctx, hantarPin)) throw new Error("קוד החנת״ר כבר בשימוש");
    if (await pinInUse(ctx, commanderPin)) throw new Error("קוד המפקד כבר בשימוש");
    const hSalt = rndHex(16), cSalt = rndHex(16);
    const classId = await ctx.db.insert("classes", {
      name: nm, iterations: ITERATIONS, createdAt: Date.now(),
      hantarSalt: hSalt, hantarHash: await pbkdf2(hantarPin, hSalt, ITERATIONS),
      commanderSalt: cSalt, commanderHash: await pbkdf2(commanderPin, cSalt, ITERATIONS),
    });
    return { classId };
  },
});

export const renameClass = mutation({
  args: { pin: v.string(), classId: v.string(), name: v.string() },
  handler: async (ctx, { pin, classId, name }) => {
    needPrincipal(pin); checkClassId(classId);
    if (classId === DEFAULT) throw new Error("לא ניתן לשנות את שם הכיתה הראשית");
    const nm = name.trim().slice(0, 60); if (!nm) throw new Error("שם הכיתה חסר");
    const c = await classById(ctx, classId); if (!c) throw new Error("כיתה לא נמצאה");
    await ctx.db.patch(c._id, { name: nm });
  },
});

// שינוי הקוד הקבוע (חנת״ר ו/או מפקד) של כיתה קיימת — רק כיתות נוספות, לא
// הכיתה הראשית (שם הקודים הקבועים הם משתני סביבה, בכוונה בלתי ניתנים לשינוי
// מתוך האפליקציה).
export const setClassPins = mutation({
  args: { pin: v.string(), classId: v.string(), hantarPin: v.optional(v.string()), commanderPin: v.optional(v.string()) },
  handler: async (ctx, { pin, classId, hantarPin, commanderPin }) => {
    needPrincipal(pin); checkClassId(classId);
    if (classId === DEFAULT) throw new Error("קודי הכיתה הראשית מוגדרים רק דרך משתני הסביבה");
    const c = await classById(ctx, classId); if (!c) throw new Error("כיתה לא נמצאה");
    const patch: Record<string, any> = {};
    if (hantarPin) { checkPin(hantarPin, "חנת״ר"); if (await pinInUse(ctx, hantarPin, { classId, field: "hantar" })) throw new Error("קוד החנת״ר כבר בשימוש"); const r = await mkPin(hantarPin); patch.hantarSalt = r.salt; patch.hantarHash = r.hash; patch.iterations = r.iterations; }
    if (commanderPin) { checkPin(commanderPin, "מפקד"); if (await pinInUse(ctx, commanderPin, { classId, field: "commander" })) throw new Error("קוד המפקד כבר בשימוש"); const r = await mkPin(commanderPin); patch.commanderSalt = r.salt; patch.commanderHash = r.hash; if (!patch.iterations) patch.iterations = r.iterations; }
    if (!Object.keys(patch).length) return;
    await ctx.db.patch(c._id, patch);
  },
});

// איפוס הקוד האישי של מפקד (כשנשכח) — חוזר לעבוד רק עם הקוד הקבוע
export const resetCommanderSelfPin = mutation({
  args: { pin: v.string(), classId: v.string() },
  handler: async (ctx, { pin, classId }) => { needPrincipal(pin); checkClassId(classId); await delSetting(ctx, classId, "commanderPin2"); },
});

export const removeClass = mutation({
  args: { pin: v.string(), classId: v.string() },
  handler: async (ctx, { pin, classId }) => {
    needPrincipal(pin); checkClassId(classId);
    if (classId === DEFAULT) throw new Error("לא ניתן למחוק את הכיתה הראשית");
    const c = await classById(ctx, classId); if (!c) return;
    for (const s of await ctx.db.query("students").withIndex("by_class", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(s._id);
    for (const s of await ctx.db.query("settings").withIndex("by_class_key", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(s._id);
    for (const t of ["marks", "closes", "cancellations", "events"] as const)
      for (const d of await ctx.db.query(t).withIndex("by_class_date", (q) => q.eq("classId", classId)).collect()) await ctx.db.delete(d._id);
    await ctx.db.delete(c._id);
  },
});
