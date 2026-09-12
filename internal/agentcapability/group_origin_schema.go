package agentcapability

// Owner-only GET turn metadata. It permits the owner's review screen to
// verify a group hint before reading its private plan/confirmation references.
// It is never an admission payload or a member authorization grant.
const groupOriginResultSchema = `{"additionalProperties":false,"properties":{"request_id":{"type":"string","format":"uuid"},"room_id":{"type":"string"},"event_id":{"type":"string"},"actor_id":{"type":"string"},"owner_id":{"type":"string"},"agent_mxid":{"type":"string"},"account_generation":{"type":"integer","minimum":1},"binding_revision":{"type":"integer","minimum":1}},"required":["request_id","room_id","event_id","actor_id","owner_id","agent_mxid","account_generation","binding_revision"],"type":"object"}`
