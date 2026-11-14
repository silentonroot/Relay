CREATE TABLE "execution_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"requested_by_user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"agent_id" uuid,
	"connection_id" uuid NOT NULL,
	"run_id" uuid,
	"operation" text,
	"arguments" jsonb,
	"retry_safe" boolean DEFAULT false NOT NULL,
	"policy_decision_id" uuid,
	"approval_request_id" uuid,
	"capability_ref" text,
	"status" text DEFAULT 'queued' NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"timeout_ms" integer NOT NULL,
	"worker_id" text,
	"lease_expires_at" timestamp (3) with time zone,
	"completion_requested_at" timestamp (3) with time zone,
	"cancel_requested_at" timestamp (3) with time zone,
	"started_at" timestamp (3) with time zone,
	"finished_at" timestamp (3) with time zone,
	"result" jsonb,
	"result_purged_at" timestamp (3) with time zone,
	"error_code" text,
	"error_message" text,
	"audit_event_id" uuid,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "execution_jobs_kind_check" CHECK ("execution_jobs"."kind" in ('operation', 'login')),
	CONSTRAINT "execution_jobs_status_check" CHECK ("execution_jobs"."status" in ('queued', 'running', 'succeeded', 'failed', 'denied', 'reauth_required', 'outcome_unknown', 'cancelled')),
	CONSTRAINT "execution_jobs_error_code_check" CHECK ("execution_jobs"."error_code" is null or "execution_jobs"."error_code" in ('denied', 'invalid_arguments', 'adapter_unavailable', 'origin_not_allowed', 'navigation_blocked', 'output_rejected', 'not_found', 'unexpected_page', 'session_expired', 'identity_mismatch', 'timeout', 'cancelled', 'worker_failure', 'login_not_completed', 'login_window_closed')),
	CONSTRAINT "execution_jobs_kind_fields_check" CHECK (("execution_jobs"."kind" = 'operation' and "execution_jobs"."agent_id" is not null and "execution_jobs"."operation" is not null and "execution_jobs"."arguments" is not null) or ("execution_jobs"."kind" = 'login' and "execution_jobs"."agent_id" is null and "execution_jobs"."operation" is null and "execution_jobs"."arguments" is null)),
	CONSTRAINT "execution_jobs_arguments_check" CHECK ("execution_jobs"."arguments" is null or jsonb_typeof("execution_jobs"."arguments") = 'object'),
	CONSTRAINT "execution_jobs_result_check" CHECK ("execution_jobs"."result" is null or jsonb_typeof("execution_jobs"."result") = 'object'),
	CONSTRAINT "execution_jobs_attempt_count_check" CHECK ("execution_jobs"."attempt_count" >= 0),
	CONSTRAINT "execution_jobs_timeout_check" CHECK ("execution_jobs"."timeout_ms" > 0)
);
--> statement-breakpoint
CREATE TABLE "operation_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"idempotency_key" text NOT NULL,
	"request_hash" text NOT NULL,
	"job_id" uuid NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "operation_requests_hash_check" CHECK ("operation_requests"."request_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "vault_secret_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"secret_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"algorithm" text NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"nonce" "bytea" NOT NULL,
	"auth_tag" "bytea" NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"kek_version" integer NOT NULL,
	"aad_version" integer NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vault_secret_versions_version_check" CHECK ("vault_secret_versions"."version" >= 1),
	CONSTRAINT "vault_secret_versions_kek_version_check" CHECK ("vault_secret_versions"."kek_version" >= 1),
	CONSTRAINT "vault_secret_versions_aad_version_check" CHECK ("vault_secret_versions"."aad_version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "vault_secrets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connection_id" uuid NOT NULL,
	"secret_type" text NOT NULL,
	"active_version_id" uuid,
	"status" text DEFAULT 'pending' NOT NULL,
	"last_version" integer DEFAULT 0 NOT NULL,
	"last_accessed_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vault_secrets_status_check" CHECK ("vault_secrets"."status" in ('pending', 'active', 'deleted')),
	CONSTRAINT "vault_secrets_last_version_check" CHECK ("vault_secrets"."last_version" >= 0)
);
--> statement-breakpoint
ALTER TABLE "connections" ADD COLUMN "session_expires_at" timestamp (3) with time zone;--> statement-breakpoint
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_connection_id_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operation_requests" ADD CONSTRAINT "operation_requests_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operation_requests" ADD CONSTRAINT "operation_requests_job_id_execution_jobs_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."execution_jobs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_secret_versions" ADD CONSTRAINT "vault_secret_versions_secret_id_vault_secrets_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."vault_secrets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_secrets" ADD CONSTRAINT "vault_secrets_connection_id_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "execution_jobs_claim_idx" ON "execution_jobs" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "execution_jobs_connection_status_idx" ON "execution_jobs" USING btree ("connection_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "execution_jobs_active_login_unique" ON "execution_jobs" USING btree ("connection_id") WHERE "execution_jobs"."kind" = 'login' and "execution_jobs"."status" in ('queued', 'running');--> statement-breakpoint
CREATE UNIQUE INDEX "operation_requests_agent_key_unique" ON "operation_requests" USING btree ("agent_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "operation_requests_job_idx" ON "operation_requests" USING btree ("job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "vault_secret_versions_secret_version_unique" ON "vault_secret_versions" USING btree ("secret_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "vault_secrets_connection_type_unique" ON "vault_secrets" USING btree ("connection_id","secret_type");