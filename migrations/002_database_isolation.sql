-- Database role isolation script
-- Prevents agent from accessing message-server database and vice versa

-- Agent database isolation
\c dirextalk_agent;

-- Revoke cross-database access from agent runtime
REVOKE CONNECT ON DATABASE dirextalk_message FROM dirextalk_agent_runtime;
REVOKE CONNECT ON DATABASE dirextalk_message FROM dirextalk_agent_migrator;

-- Message-Server database isolation
\c dirextalk_message;

-- Revoke cross-database access from message-server runtime
REVOKE CONNECT ON DATABASE dirextalk_agent FROM dirextalk_message_runtime;
REVOKE CONNECT ON DATABASE dirextalk_agent FROM dirextalk_message_migrator;

-- Verify isolation
SELECT
    datname as database,
    rolname as role,
    has_database_privilege(rolname, datname, 'CONNECT') as can_connect
FROM pg_database, pg_roles
WHERE datname IN ('dirextalk_agent', 'dirextalk_message')
  AND rolname LIKE 'dirextalk_%'
ORDER BY datname, rolname;
