import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// חנת״ר + — סכמת נתונים.
// sid = מזהה תלמיד שנוצר בצד הלקוח (יציב, מאפשר upsert בטוח).
export default defineSchema({
  students: defineTable({
    sid: v.string(),
    name: v.string(),
    order: v.number(),
  }).index("by_sid", ["sid"]),

  // מפתחות: "schedule" (שעות מסדר סיום שבועיות), "demo", "cmd" (כניסת המפקד)
  settings: defineTable({
    key: v.string(),
    value: v.any(),
  }).index("by_key", ["key"]),

  // סימון נוכחות: P=נוכח, A=חיסור, L=הודיע על איחור. late=הגיע באיחור.
  marks: defineTable({
    date: v.string(), // YYYY-MM-DD
    sid: v.string(),
    s: v.union(v.literal("P"), v.literal("A"), v.literal("L")),
    late: v.optional(v.boolean()),
    at: v.number(),
    arr: v.optional(v.number()),
    eta: v.optional(v.string()),
    note: v.optional(v.string()),
  })
    .index("by_date", ["date"])
    .index("by_date_sid", ["date", "sid"]),

  // שעת מסדר סיום מעודכנת ליום מסוים (override לשעה השבועית הקבועה)
  closes: defineTable({
    date: v.string(),
    time: v.string(), // HH:MM
    orig: v.string(),
    reason: v.optional(v.string()),
    note: v.optional(v.string()),
    at: v.number(),
    ackAt: v.optional(v.number()), // אישור קבלה של המפקד
  }).index("by_date", ["date"]),

  // יומן אירועים (מזין את "עדכונים אחרונים" אצל המפקד)
  events: defineTable({
    date: v.string(),
    ts: v.number(),
    k: v.string(), // mark | close | ack | bulk
    sid: v.optional(v.string()),
    name: v.optional(v.string()),
    st: v.optional(v.string()),
    late: v.optional(v.boolean()),
    eta: v.optional(v.string()),
    time: v.optional(v.string()),
    orig: v.optional(v.string()),
    reason: v.optional(v.string()),
    n: v.optional(v.number()),
  }).index("by_date", ["date"]),
});    orig: v.string(),
    reason: v.optional(v.string()),
    note: v.optional(v.string()),
    at: v.number(),
    ackAt: v.optional(v.number()), // אישור קבלה של המפקד
  }).index("by_date", ["date"]),

  // יומן אירועים (מזין את "עדכונים אחרונים" אצל המפקד)
  events: defineTable({
    date: v.string(),
    ts: v.number(),
    k: v.string(), // mark | close | ack | bulk
    sid: v.optional(v.string()),
    name: v.optional(v.string()),
    st: v.optional(v.string()),
    late: v.optional(v.boolean()),
    eta: v.optional(v.string()),
    time: v.optional(v.string()),
    orig: v.optional(v.string()),
    reason: v.optional(v.string()),
    n: v.optional(v.number()),
  }).index("by_date", ["date"]),
});
