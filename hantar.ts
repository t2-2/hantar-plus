import { query, mutation } from "./_generated/server";
import { v } from "convex/values";

/* ============================================================
   חנת״ר + — פונקציות שרת (Convex)
   הרשאות: קודי כניסה נבדקים בשרת מול משתני סביבה:
     npx convex env set HANTAR_PIN <קוד>
     npx convex env set COMMANDER_PIN <קוד>
   קוד ארוך (6+ ספרות) מומלץ. ללא משתני הסביבה — כל הקריאות נדחות.
   חנת״ר: כתיבה מלאה. מפקד: קריאה + אישור קבלה + תיעוד כניסה.
   ============================================================ */

type Role = "hantar" | "commander";

function roleOf(pin: string): Role | null {
  const h = process.env.HANTAR_PIN;
  const c = process.env.COMMANDER_PIN;
  if (h && pin === h) return "hantar";
  if (c && pin === c) return "commander";
  return null;
}
function need(pin: string, allowed: Role[]): Role {
  const r = roleOf(pin);
  if (!r || !allowed.includes(r)) throw new Error("אין הרשאה");
  return r;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const checkDate = (d: string) => { if (!DATE.test(d)) throw new Error("תאריך לא תקין"); };
const checkTime = (t: string) => { if (!TIME.test(t)) throw new Error("שעה לא תקינה"); };

const markV = v.object({
  s: v.union(v.literal("P"), v.literal("A"), v.literal("L")),
  at: v.number(),
  late: v.optional(v.boolean()),
  arr: v.optional(v.number()),
  eta: v.optional(v.string()),
  note: v.optional(v.string()),
});
const evV = v.object({
  ts: v.number(),
  k: v.string(),
  date: v.optional(v.string()),
  sid: v.optional(v.string()),
  name: v.optional(v.string()),
  st: v.optional(v.string()),
  late: v.optional(v.boolean()),
  eta: v.optional(v.string()),
  time: v.optional(v.string()),
  orig: v.optional(v.string()),
  reason: v.optional(v.string()),
  n: v.optional(v.number()),
});

async function setSetting(ctx: any, key: string, value: any) {
  const ex = await ctx.db.query("settings").withIndex("by_key", (q: any) => q.eq("key", key)).first();
  if (ex) await ctx.db.patch(ex._id, { value });
  else await ctx.db.insert("settings", { key, value });
}
async function addEvent(ctx: any, date: string, ev: any) {
  if (!ev) return;
  const { date: _d, ...rest } = ev;
  await ctx.db.insert("events", { date, ...rest });
}
async function upsertMark(ctx: any, date: string, sid: string, mark: any | null) {
  const ex = await ctx.db.query("marks").withIndex("by_date_sid", (q: any) => q.eq("date", date).eq("sid", sid)).first();
  if (mark) {
    if (ex) await ctx.db.replace(ex._id, { date, sid, ...mark });
    else await ctx.db.insert("marks", { date, sid, ...mark });
  } else if (ex) {
    await ctx.db.delete(ex._id);
  }
}

/* ---------- קריאה ---------- */

export const whoami = query({
  args: { pin: v.string() },
  handler: async (_ctx, { pin }) => roleOf(pin),
});

// תמונת מצב מלאה (reactive): כל לקוח מחובר מתעדכן מיד כשמשהו משתנה.
export const snapshot = query({
  args: { pin: v.string(), since: v.string() },
  handler: async (ctx, { pin, since }) => {
    need(pin, ["hantar", "commander"]);
    checkDate(since);
    const students = (await ctx.db.query("students").collect()).sort((a, b) => a.order - b.order).map((s) => ({ id: s.sid, name: s.name }));
    const settings: Record<string, any> = {};
    for (const s of await ctx.db.query("settings").collect()) settings[s.key] = s.value;
    const days: Record<string, any> = {};
    const day = (d: string) => (days[d] ??= { marks: {}, events: [] });
    for (const m of await ctx.db.query("marks").withIndex("by_date", (q) => q.gte("date", since)).collect()) {
      const { _id, _creationTime, date, sid, ...mark } = m as any;
      day(date).marks[sid] = mark;
    }
    for (const c of await ctx.db.query("closes").withIndex("by_date", (q) => q.gte("date", since)).collect()) {
      const { _id, _creationTime, date, ...close } = c as any;
      day(date).close = close;
    }
    for (const e of await ctx.db.query("events").withIndex("by_date", (q) => q.gte("date", since)).collect()) {
      const { _id, _creationTime, ...ev } = e as any;
      day(e.date).events.push(ev);
    }
    for (const d of Object.values(days)) (d as any).events.sort((a: any, b: any) => a.ts - b.ts);
    return {
      students,
      config: { schedule: settings.schedule ?? null, demo: !!settings.demo },
      meta: { cmd: settings.cmd ?? null },
      days,
    };
  },
});

/* ---------- כתיבה: חנת״ר ---------- */

export const mark = mutation({
  args: { pin: v.string(), date: v.string(), sid: v.string(), mark: v.union(markV, v.null()), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    need(a.pin, ["hantar"]); checkDate(a.date);
    await upsertMark(ctx, a.date, a.sid, a.mark);
    await addEvent(ctx, a.date, a.ev);
  },
});

export const markMany = mutation({
  args: { pin: v.string(), date: v.string(), entries: v.array(v.object({ sid: v.string(), mark: v.union(markV, v.null()) })), ev: v.optional(v.union(evV, v.null())) },
  handler: async (ctx, a) => {
    need(a.pin, ["hantar"]); checkDate(a.date);
    if (a.entries.length > 500) throw new Error("יותר מדי רשומות");
    for (const e of a.entries) await upsertMark(ctx, a.date, e.sid, e.mark);
    await addEvent(ctx, a.date, a.ev);
  },
});

export const setStudents = mutation({
  args: { pin: v.string(), list: v.array(v.object({ id: v.string(), name: v.string() })) },
  handler: async (ctx, { pin, list }) => {
    need(pin, ["hantar"]);
    if (list.length > 500) throw new Error("יותר מדי תלמידים");
    const existing = await ctx.db.query("students").collect();
    const bySid = new Map(existing.map((s) => [s.sid, s]));
    const keep = new Set<string>();
    for (let i = 0; i < list.length; i++) {
      const name = list[i].name.trim().slice(0, 80);
      if (!name) continue;
      keep.add(list[i].id);
      const ex = bySid.get(list[i].id);
      if (ex) await ctx.db.patch(ex._id, { name, order: i });
      else await ctx.db.insert("students", { sid: list[i].id, name, order: i });
    }
    for (const s of existing) if (!keep.has(s.sid)) await ctx.db.delete(s._id);
  },
});

export const setSchedule = mutation({
  args: { pin: v.string(), schedule: v.any() },
  handler: async (ctx, { pin, schedule }) => {
    need(pin, ["hantar"]);
    const out: Record<string, string> = {};
    for (let d = 0; d <= 6; d++) {
      const t = String(schedule?.[d] ?? "");
      if (t) checkTime(t);
      out[String(d)] = t;
    }
    await setSetting(ctx, "schedule", out);
  },
});

export const setDemo = mutation({
  args: { pin: v.string(), on: v.boolean() },
  handler: async (ctx, { pin, on }) => { need(pin, ["hantar"]); await setSetting(ctx, "demo", on); },
});

// עדכון שעת מסדר סיום — מאפס אישור קבלה קודם (המפקד צריך לאשר מחדש)
export const setClose = mutation({
  args: {
    pin: v.string(), date: v.string(),
    close: v.object({ time: v.string(), orig: v.string(), reason: v.optional(v.string()), note: v.optional(v.string()), at: v.number() }),
    ev: v.optional(v.union(evV, v.null())),
  },
  handler: async (ctx, a) => {
    need(a.pin, ["hantar"]); checkDate(a.date); checkTime(a.close.time);
    const ex = await ctx.db.query("closes").withIndex("by_date", (q) => q.eq("date", a.date)).first();
    if (ex) await ctx.db.replace(ex._id, { date: a.date, ...a.close });
    else await ctx.db.insert("closes", { date: a.date, ...a.close });
    await addEvent(ctx, a.date, a.ev);
  },
});

// טעינת מצב שלם (נתוני הדגמה / ייבוא) — מוחק הכול ומחליף
export const importState = mutation({
  args: { pin: v.string(), state: v.any() },
  handler: async (ctx, { pin, state }) => {
    need(pin, ["hantar"]);
    for (const t of ["students", "settings", "marks", "closes", "events"] as const)
      for (const d of await ctx.db.query(t).collect()) await ctx.db.delete(d._id);
    const students: { id: string; name: string }[] = state?.students ?? [];
    for (let i = 0; i < students.length; i++) await ctx.db.insert("students", { sid: students[i].id, name: String(students[i].name).slice(0, 80), order: i });
    const sch = state?.config?.schedule;
    if (sch) await setSetting(ctx, "schedule", sch);
    await setSetting(ctx, "demo", !!state?.config?.demo);
    for (const [date, day] of Object.entries<any>(state?.days ?? {})) {
      checkDate(date);
      for (const [sid, m] of Object.entries<any>(day.marks ?? {})) await ctx.db.insert("marks", { date, sid, ...m });
      if (day.close) await ctx.db.insert("closes", { date, ...day.close });
      for (const e of day.events ?? []) { const { date: _d, ...rest } = e; await ctx.db.insert("events", { date, ...rest }); }
    }
  },
});

/* ---------- כתיבה: מפקד ---------- */

export const ack = mutation({
  args: { pin: v.string(), date: v.string(), ts: v.number() },
  handler: async (ctx, { pin, date, ts }) => {
    need(pin, ["commander"]); checkDate(date);
    const c = await ctx.db.query("closes").withIndex("by_date", (q) => q.eq("date", date)).first();
    if (!c) return;
    await ctx.db.patch(c._id, { ackAt: ts });
    await ctx.db.insert("events", { date, ts, k: "ack", time: c.time });
  },
});

export const cmdEnter = mutation({
  args: { pin: v.string(), ts: v.number(), prev: v.optional(v.union(v.number(), v.null())) },
  handler: async (ctx, { pin, ts, prev }) => {
    need(pin, ["commander"]);
    await setSetting(ctx, "cmd", { enteredAt: ts, prev: prev ?? null });
  },
});
