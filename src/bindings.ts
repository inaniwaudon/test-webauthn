export type Bindings = {
  KV: KVNamespace;
  DB: D1Database;
};

declare global {
  function getMiniflareBindings(): Bindings;
}
