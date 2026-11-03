import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// חנת״ר + — סכמת נתונים.
// כל שורה (מלבד classes) שייכת לכיתה מסוימת דרך classId:
//   - הכיתה הראשית (ברירת מחדל) משתמשת ב-classId הקבוע "default", ומאומתת מול
//     משתני הסביבה HANTAR_PIN / COMMANDER_PIN (ללא טרמינל: Convex Dashboard ← Settings ← Environment Variables).
//   - כיתות נוספות נוצרות מתוך האפליקציה (כפתור נסתר) ומאוחסנות כאן, עם קודים
//     שמורים כ-hash (PBKDF2 + salt) — לא כטקסט גלוי.
// כל שאילתה וכל כתיבה מסוננות לפי classId, כך שנתונים של כיתה אחת לעולם לא
// מגיעים ללקוח של כיתה אחרת, גם אם שתיהן מחוברות באותו רגע.
export default defineSchema({
  classes: defineTable({
    name: v.string(),
    hantarSalt: v.string(),
    hantarHash: v.string(),
    commanderSalt: v.string(),
    commanderHash: v.string(),
    iterations: v.number(),
    createdAt: v.number(),
  }),

  students: defineTable({
    classId: v.string(),
    sid: v.string(),
    name: v.string(),
    order: v.number(),
  })
    .index("by_class", ["classId"])
    .index("by_class_sid", ["classId", "sid"]),

  // מפתחות: "schedule" (שעות מסדר סיום שבועיות, ראשון-חמישי), "demo", "cmd" (כניסת המפקד)
  settings: defineTable({
    classId: v.string(),
    key: v.string(),
    value: v.any(),
  }).index("by_class_key", ["classId", "key"]),

  // סימון נוכחות: P=נוכח, A=חיסור, L=הודיע על איחור. late=הגיע באיחור.
  // כל יום מתחיל "ריק" ממילא (כל רשומה שייכת לתאריך שלה) — זה האיפוס היומי בחצות.
  marks: defineTable({
    classId: v.string(),
    date: v.string(), // YYYY-MM-DD
    sid: v.string(),
    s: v.union(v.literal("P"), v.literal("A"), v.literal("L")),
    late: v.optional(v.boolean()),
    at: v.number(),
    arr: v.optional(v.number()),
    eta: v.optional(v.string()),
    note: v.optional(v.string()),
  })
    .index("by_class_date", ["classId", "date"])
    .index("by_class_date_sid", ["classId", "date", "sid"]),

  // שעת מסדר סיום מעודכנת ליום מסוים (override לשעה השבועית הקבועה)
  closes: defineTable({
    classId: v.string(),
    date: v.string(),
    time: v.string(), // HH:MM
    orig: v.string(),
    reason: v.optional(v.string()),
    note: v.optional(v.string()),
    at: v.number(),
    ackAt: v.optional(v.number()), // אישור קבלה של המפקד
  }).index("by_class_date", ["classId", "date"]),

  // ביטול מסדר ליום מסוים, ביוזמת המפקד
  cancellations: defineTable({
    classId: v.string(),
    date: v.string(),
    reason: v.optional(v.string()),
    note: v.optional(v.string()),
    at: v.number(),
  }).index("by_class_date", ["classId", "date"]),

  // יומן אירועים (מזין את "עדכונים אחרונים" אצל המפקד)
  events: defineTable({
    classId: v.string(),
    date: v.string(),
    ts: v.number(),
    k: v.string(), // mark | close | ack | bulk | cancel | uncancel
    sid: v.optional(v.string()),
    name: v.optional(v.string()),
    st: v.optional(v.string()),
    late: v.optional(v.boolean()),
    eta: v.optional(v.string()),
    time: v.optional(v.string()),
    orig: v.optional(v.string()),
    reason: v.optional(v.string()),
    n: v.optional(v.number()),
  }).index("by_class_date", ["classId", "date"]),
});
