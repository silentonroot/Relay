DROP INDEX "agents_client_identity_unique";--> statement-breakpoint
CREATE UNIQUE INDEX "agents_owner_client_identity_unique" ON "agents" USING btree ("owner_user_id","client_identity");