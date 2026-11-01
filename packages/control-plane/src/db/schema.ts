import { pgTable, text, timestamp, integer, boolean, uuid, index } from "drizzle-orm/pg-core";

export const orgs = pgTable("orgs", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  plan: text("plan").notNull().default("community"), // community, pro, enterprise
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const nodes = pgTable("nodes", {
  id: text("id").primaryKey(), // node_e7adede03740be62
  orgId: uuid("org_id").notNull().references(() => orgs.id, { onDelete: "cascade" }),
  publicKeyPem: text("public_key_pem").notNull(),
  status: text("status").notNull().default("active"),
  lastSeenAt: timestamp("last_seen_at").defaultNow().notNull(),
}, (table) => [
  index("nodes_org_id_idx").on(table.orgId),
]);

export const virtualKeys = pgTable("virtual_keys", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => orgs.id, { onDelete: "cascade" }),
  keyHash: text("key_hash").notNull().unique(), // hashed vk-aindigo-...
  name: text("name").notNull(),
  upstreamProvider: text("upstream_provider").notNull(), // openai, anthropic, google
  encryptedUpstreamKey: text("encrypted_upstream_key").notNull(), // envelope encrypted DEK
  revoked: boolean("revoked").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("virtual_keys_org_id_idx").on(table.orgId),
]);

export const receipts = pgTable("receipts", {
  receiptId: text("receipt_id").primaryKey(),
  orgId: uuid("org_id").notNull().references(() => orgs.id, { onDelete: "cascade" }),
  nodeId: text("node_id").notNull(),
  timestamp: text("timestamp").notNull(),
  department: text("department").notNull(),
  modelRequested: text("model_requested").notNull(),
  modelRouted: text("model_routed").notNull(),
  promptTokens: integer("prompt_tokens").notNull(),
  completionTokens: integer("completion_tokens").notNull(),
  costUsd: text("cost_usd").notNull(), // stored as string for precision
  dlpCategories: text("dlp_categories").array().notNull(),
  cacheHit: boolean("cache_hit").notNull(),
  prevHash: text("prev_hash").notNull(),
  receiptHash: text("receipt_hash").notNull(),
  ed25519Signature: text("ed25519_signature").notNull(),
}, (table) => [
  index("receipts_org_id_idx").on(table.orgId),
  index("receipts_node_id_idx").on(table.nodeId),
]);
