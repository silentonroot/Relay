-- Hand-written: drizzle-kit cannot generate triggers. Threat model F-7 / DB-6.
--
-- Makes audit_events append-only at the database level: any UPDATE, DELETE or TRUNCATE
-- raises an exception, whoever issues it, so SQL injection elsewhere or a mistaken script
-- cannot silently rewrite history.
--
-- LIMITATION: this raises the bar, it does not make the log immutable. The table owner or a
-- database superuser can still run
--   ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update_delete;
-- (or drop the triggers, or use session_replication_role = replica) and then edit rows.
-- Detecting that remains the job of the hash chain plus an exported head checkpoint, and of
-- running the API under a least-privilege role that does not own the table.
CREATE FUNCTION "audit_events_reject_change"() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "audit_events_no_update_delete"
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW EXECUTE FUNCTION "audit_events_reject_change"();
--> statement-breakpoint
CREATE TRIGGER "audit_events_no_truncate"
  BEFORE TRUNCATE ON "audit_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "audit_events_reject_change"();
