-- cloud_resources may be created by either the original Worker-plan approval
-- or a separately device-approved public-entry operation.  The old foreign
-- key admitted only the former and rejected a correctly approved ALB/TLS
-- resource before the typed resource-origin verifier could persist its
-- intent.  A polymorphic foreign key is not safe here: every resource origin
-- is instead checked against its exact approved Worker plan or Entry
-- operation, scope, owner, connection, deployment, and manifest binding.

ALTER TABLE cloud_resources
    DROP CONSTRAINT IF EXISTS cloud_resources_approval_fk;
