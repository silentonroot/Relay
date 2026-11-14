import { defineConfig } from 'drizzle-kit';

// `drizzle-kit generate` only diffs src/schema.ts against the committed snapshots in
// drizzle/meta. It never connects to a database, so no credentials belong here.
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema.ts',
  out: './drizzle',
});
