CREATE TABLE "agent_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"connection_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"effect" text NOT NULL,
	"constraints" jsonb NOT NULL,
	"approval_mode" text NOT NULL,
	"expires_at" timestamp (3) with time zone,
	"revoked_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_grants_effect_check" CHECK ("agent_grants"."effect" in ('allow', 'deny')),
	CONSTRAINT "agent_grants_approval_mode_check" CHECK ("agent_grants"."approval_mode" in ('none', 'required')),
	CONSTRAINT "agent_grants_constraints_check" CHECK (jsonb_typeof("agent_grants"."constraints") = 'object')
);
--> statement-breakpoint
CREATE TABLE "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"owner_user_id" uuid NOT NULL,
	"name" text NOT NULL,
	"client_identity" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agents_status_check" CHECK ("agents"."status" in ('active', 'disabled'))
);
--> statement-breakpoint
CREATE TABLE "application_definitions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"adapter_id" text NOT NULL,
	"adapter_version" text NOT NULL,
	"name" text NOT NULL,
	"allowed_origins" jsonb NOT NULL,
	"auth_modes" jsonb NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "application_definitions_status_check" CHECK ("application_definitions"."status" in ('active', 'disabled')),
	CONSTRAINT "application_definitions_origins_check" CHECK (jsonb_typeof("application_definitions"."allowed_origins") = 'array' and jsonb_array_length("application_definitions"."allowed_origins") > 0),
	CONSTRAINT "application_definitions_auth_modes_check" CHECK (jsonb_typeof("application_definitions"."auth_modes") = 'array' and jsonb_array_length("application_definitions"."auth_modes") > 0)
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"sequence" bigint NOT NULL,
	"timestamp" timestamp (3) with time zone NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" uuid,
	"agent_id" uuid,
	"run_id" uuid,
	"connection_id" uuid,
	"event_type" text NOT NULL,
	"decision" text NOT NULL,
	"metadata" jsonb NOT NULL,
	"previous_hash" text,
	"event_hash" text NOT NULL,
	CONSTRAINT "audit_events_sequence_check" CHECK ("audit_events"."sequence" >= 1),
	CONSTRAINT "audit_events_actor_type_check" CHECK ("audit_events"."actor_type" in ('user', 'agent', 'worker', 'system')),
	CONSTRAINT "audit_events_decision_check" CHECK ("audit_events"."decision" in ('allow', 'deny', 'approval_required', 'not_applicable')),
	CONSTRAINT "audit_events_event_type_check" CHECK ("audit_events"."event_type" ~ '^[a-z_]+\.[a-z_]+$'),
	CONSTRAINT "audit_events_metadata_check" CHECK (jsonb_typeof("audit_events"."metadata") = 'object'),
	CONSTRAINT "audit_events_event_hash_check" CHECK ("audit_events"."event_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "audit_events_chain_start_check" CHECK (("audit_events"."sequence" = 1) = ("audit_events"."previous_hash" is null))
);
--> statement-breakpoint
CREATE TABLE "connection_status_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connection_id" uuid NOT NULL,
	"from_status" text,
	"to_status" text NOT NULL,
	"reason" text,
	"actor_type" text NOT NULL,
	"actor_id" uuid,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "connection_status_events_from_status_check" CHECK ("connection_status_events"."from_status" is null or "connection_status_events"."from_status" in ('created', 'authentication_required', 'authenticating', 'active', 'degraded', 'expired', 'reconnect_required', 'revoked')),
	CONSTRAINT "connection_status_events_to_status_check" CHECK ("connection_status_events"."to_status" in ('created', 'authentication_required', 'authenticating', 'active', 'degraded', 'expired', 'reconnect_required', 'revoked')),
	CONSTRAINT "connection_status_events_actor_type_check" CHECK ("connection_status_events"."actor_type" in ('user', 'agent', 'worker', 'system'))
);
--> statement-breakpoint
CREATE TABLE "connections" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"owner_user_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"application_id" uuid NOT NULL,
	"display_name" text NOT NULL,
	"external_account_hint" text,
	"status" text DEFAULT 'created' NOT NULL,
	"status_reason" text,
	"last_verified_at" timestamp (3) with time zone,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "connections_status_check" CHECK ("connections"."status" in ('created', 'authentication_required', 'authenticating', 'active', 'degraded', 'expired', 'reconnect_required', 'revoked'))
);
--> statement-breakpoint
CREATE TABLE "memberships" (
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "memberships_pk" PRIMARY KEY("organization_id","user_id"),
	CONSTRAINT "memberships_role_check" CHECK ("memberships"."role" in ('owner', 'admin', 'member'))
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organizations_status_check" CHECK ("organizations"."status" in ('active', 'disabled'))
);
--> statement-breakpoint
CREATE TABLE "user_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"csrf_token_hash" text NOT NULL,
	"expires_at" timestamp (3) with time zone NOT NULL,
	"revoked_at" timestamp (3) with time zone,
	"last_seen_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_lowercase_check" CHECK ("users"."email" = lower("users"."email")),
	CONSTRAINT "users_status_check" CHECK ("users"."status" in ('active', 'disabled'))
);
--> statement-breakpoint
ALTER TABLE "agent_grants" ADD CONSTRAINT "agent_grants_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_grants" ADD CONSTRAINT "agent_grants_connection_id_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "application_definitions" ADD CONSTRAINT "application_definitions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connection_status_events" ADD CONSTRAINT "connection_status_events_connection_id_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connections" ADD CONSTRAINT "connections_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connections" ADD CONSTRAINT "connections_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connections" ADD CONSTRAINT "connections_application_id_application_definitions_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."application_definitions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_grants_evaluation_idx" ON "agent_grants" USING btree ("agent_id","connection_id","operation");--> statement-breakpoint
CREATE INDEX "agent_grants_agent_list_idx" ON "agent_grants" USING btree ("agent_id","created_at","id");--> statement-breakpoint
CREATE INDEX "agent_grants_connection_idx" ON "agent_grants" USING btree ("connection_id");--> statement-breakpoint
CREATE UNIQUE INDEX "agents_client_identity_unique" ON "agents" USING btree ("organization_id","client_identity");--> statement-breakpoint
CREATE INDEX "agents_list_idx" ON "agents" USING btree ("organization_id","owner_user_id","created_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "application_definitions_adapter_unique" ON "application_definitions" USING btree ("organization_id","adapter_id","adapter_version");--> statement-breakpoint
CREATE INDEX "application_definitions_list_idx" ON "application_definitions" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_org_sequence_unique" ON "audit_events" USING btree ("organization_id","sequence");--> statement-breakpoint
CREATE INDEX "audit_events_connection_idx" ON "audit_events" USING btree ("organization_id","connection_id");--> statement-breakpoint
CREATE INDEX "audit_events_agent_idx" ON "audit_events" USING btree ("organization_id","agent_id");--> statement-breakpoint
CREATE INDEX "audit_events_event_type_idx" ON "audit_events" USING btree ("organization_id","event_type");--> statement-breakpoint
CREATE INDEX "connection_status_events_connection_idx" ON "connection_status_events" USING btree ("connection_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "connections_owner_application_name_unique" ON "connections" USING btree ("owner_user_id","application_id","display_name");--> statement-breakpoint
CREATE INDEX "connections_list_idx" ON "connections" USING btree ("organization_id","owner_user_id","created_at","id");--> statement-breakpoint
CREATE INDEX "connections_application_idx" ON "connections" USING btree ("application_id");--> statement-breakpoint
CREATE INDEX "memberships_user_idx" ON "memberships" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_sessions_token_hash_unique" ON "user_sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "user_sessions_user_idx" ON "user_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "user_sessions_expires_at_idx" ON "user_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_unique" ON "users" USING btree ("email");