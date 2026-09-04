-- Manual Network Encryptor configuration for profile 23.
--
-- Topology:
--   Br0: LAN enp1s0f0np0 <-> WAN enp2s0f0np0
--   Br1: LAN enp1s0f1np1 <-> WAN enp2s0f1np1
--   PQC tunnel: t_PQC, local 10.0.0.1, peer 10.0.0.2
--   Policy 1: Layer-2 PQC, protocol/IP/port ANY
--
-- Run with psql against the NE database. This file is intentionally
-- idempotent for the rows owned by profile 23. It does not fabricate or
-- overwrite PQC identity material in pqc_keys/HashiCorp Vault.

BEGIN;

INSERT INTO ne_profiles (
    id, name, description,
    weight_enable, loss_enable, latency_enable,
    bridge_enable, tunnel_enable,
    created_by, updated_at, updated_by
) VALUES (
    23, 'manual-pqc-l2-profile-23', 'Manual two-path L2 PQC profile',
    TRUE, FALSE, FALSE,
    TRUE, TRUE,
    'manual-sql', NOW(), 'manual-sql'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    weight_enable = EXCLUDED.weight_enable,
    loss_enable = EXCLUDED.loss_enable,
    latency_enable = EXCLUDED.latency_enable,
    latency_duration = NULL,
    loss_duration = NULL,
    bridge_enable = EXCLUDED.bridge_enable,
    tunnel_enable = EXCLUDED.tunnel_enable,
    updated_at = NOW(),
    updated_by = EXCLUDED.updated_by;

-- Replace only interface membership owned by profile 23.
DELETE FROM ne_lan WHERE profile_id = 23;
DELETE FROM ne_wan WHERE profile_id = 23;

INSERT INTO ne_lan (interface, profile_id) VALUES
    ('enp1s0f0np0', 23),
    ('enp1s0f1np1', 23);

INSERT INTO ne_wan (
    interface, profile_id, dst_ip, weight,
    latency_ip, latency, latency_enable,
    loss_ip, loss_percentage, loss_enable
) VALUES
    ('enp2s0f0np0', 23, NULL, 50, NULL, NULL, FALSE, NULL, NULL, FALSE),
    ('enp2s0f1np1', 23, NULL, 50, NULL, NULL, FALSE, NULL, NULL, FALSE);

DO $setup$
DECLARE
    v_br0 UUID;
    v_br1 UUID;
    v_tunnel UUID;
BEGIN
    SELECT id INTO v_br0
      FROM bridges
     WHERE ifname = 'Br0'
     ORDER BY created_at NULLS LAST, id
     LIMIT 1;

    IF v_br0 IS NULL THEN
        INSERT INTO bridges (ifname, description, created_by, updated_by)
        VALUES ('Br0', 'LAN0/WAN0 bridge for profile 23', 'manual-sql', 'manual-sql')
        RETURNING id INTO v_br0;
    ELSE
        UPDATE bridges
           SET description = 'LAN0/WAN0 bridge for profile 23',
               updated_at = NOW(), updated_by = 'manual-sql'
         WHERE id = v_br0;
    END IF;

    SELECT id INTO v_br1
      FROM bridges
     WHERE ifname = 'Br1'
     ORDER BY created_at NULLS LAST, id
     LIMIT 1;

    IF v_br1 IS NULL THEN
        INSERT INTO bridges (ifname, description, created_by, updated_by)
        VALUES ('Br1', 'LAN1/WAN1 bridge for profile 23', 'manual-sql', 'manual-sql')
        RETURNING id INTO v_br1;
    ELSE
        UPDATE bridges
           SET description = 'LAN1/WAN1 bridge for profile 23',
               updated_at = NOW(), updated_by = 'manual-sql'
         WHERE id = v_br1;
    END IF;

    -- A bridge is global configuration, so make each selected bridge contain
    -- exactly the LAN/WAN pair shown by `ip link`.
    DELETE FROM bridge_interfaces WHERE bridge_id IN (v_br0, v_br1);
    INSERT INTO bridge_interfaces (bridge_id, ifname, tag) VALUES
        (v_br0, 'enp1s0f0np0', 'LAN'),
        (v_br0, 'enp2s0f0np0', 'WAN'),
        (v_br1, 'enp1s0f1np1', 'LAN'),
        (v_br1, 'enp2s0f1np1', 'WAN');

    DELETE FROM profile_bridge_ref WHERE profile_id = 23;
    INSERT INTO profile_bridge_ref (profile_id, bridge_id) VALUES
        (23, v_br0),
        (23, v_br1);

    SELECT id INTO v_tunnel
      FROM pqc_exchange_tunnels
     WHERE tunnel_name = 't_PQC'
     ORDER BY created_at NULLS LAST, id
     LIMIT 1;

    IF v_tunnel IS NULL THEN
        INSERT INTO pqc_exchange_tunnels (
            tunnel_name, mode, tunnel_ip, peer_tunnel_ip,
            created_by, updated_by
        ) VALUES (
            't_PQC', 'server', '10.0.0.1', '10.0.0.2',
            'manual-sql', 'manual-sql'
        ) RETURNING id INTO v_tunnel;
    ELSE
        -- Keep any WireGuard/private/public fields already provisioned by BE.
        UPDATE pqc_exchange_tunnels
           SET tunnel_name = 't_PQC',
               tunnel_ip = '10.0.0.1',
               peer_tunnel_ip = '10.0.0.2',
               updated_at = NOW(),
               updated_by = 'manual-sql'
         WHERE id = v_tunnel;
    END IF;

    DELETE FROM profile_tunnel_ref WHERE profile_id = 23;
    INSERT INTO profile_tunnel_ref (profile_id, tunnel_id)
    VALUES (23, v_tunnel);
END
$setup$;

-- Keep policy id=1 as requested. NULL protocol means ANY; explicit 'any'
-- array entries are accepted by the current DB parser for IP and ports.
INSERT INTO ne_policies (
    id, profile_id, priority, action, proto,
    src_ip, dst_ip, src_port, dst_port,
    invert_src_ip, invert_dst_ip,
    method, encryption_key
) VALUES (
    1, 23, 1, 'L2', NULL,
    ARRAY['any']::TEXT[], ARRAY['any']::TEXT[],
    ARRAY['any']::TEXT[], ARRAY['any']::TEXT[],
    FALSE, FALSE,
    'pqc-gcm', NULL
)
ON CONFLICT (id) DO UPDATE SET
    profile_id = EXCLUDED.profile_id,
    priority = EXCLUDED.priority,
    action = EXCLUDED.action,
    proto = EXCLUDED.proto,
    src_ip = EXCLUDED.src_ip,
    dst_ip = EXCLUDED.dst_ip,
    src_port = EXCLUDED.src_port,
    dst_port = EXCLUDED.dst_port,
    invert_src_ip = EXCLUDED.invert_src_ip,
    invert_dst_ip = EXCLUDED.invert_dst_ip,
    method = EXCLUDED.method,
    encryption_key = EXCLUDED.encryption_key;

-- Bind policy 1 to the already-provisioned PQC identity key_id='1'.
-- pqc_keys.key_id is VARCHAR in schema.sql, therefore the value is quoted.
-- The INSERT intentionally fails and rolls the transaction back if key_id='1'
-- does not exist: NE must never start this policy with an ambiguous identity.
DELETE FROM policy_pqc_ref WHERE policy_id = 1;
INSERT INTO policy_pqc_ref (policy_id, key_id, created_at)
VALUES (1, '1', NOW());

-- Explicit SERIAL ids must not leave their sequences behind.
SELECT setval(
    pg_get_serial_sequence('ne_profiles', 'id'),
    GREATEST((SELECT COALESCE(MAX(id), 1) FROM ne_profiles), 1),
    TRUE
);
SELECT setval(
    pg_get_serial_sequence('ne_policies', 'id'),
    GREATEST((SELECT COALESCE(MAX(id), 1) FROM ne_policies), 1),
    TRUE
);

DO $check_key$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM policy_pqc_ref r
          JOIN pqc_keys k ON k.key_id = r.key_id
         WHERE r.policy_id = 1
           AND r.key_id = '1'
           AND NULLIF(k.local, '') IS NOT NULL
           AND NULLIF(k.remote, '') IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'pqc_keys.key_id=1 exists but local/remote PQC identity is empty';
    END IF;
END
$check_key$;

COMMIT;

-- Verification result set.
SELECT id, name, weight_enable, bridge_enable, tunnel_enable
  FROM ne_profiles WHERE id = 23;
SELECT profile_id, interface FROM ne_lan WHERE profile_id = 23 ORDER BY interface;
SELECT profile_id, interface, weight, dst_ip FROM ne_wan WHERE profile_id = 23 ORDER BY interface;
SELECT pbr.profile_id, b.ifname AS bridge, bi.tag, bi.ifname AS member
  FROM profile_bridge_ref pbr
  JOIN bridges b ON b.id = pbr.bridge_id
  JOIN bridge_interfaces bi ON bi.bridge_id = b.id
 WHERE pbr.profile_id = 23
 ORDER BY b.ifname, bi.tag;
SELECT ptr.profile_id, t.tunnel_name, t.mode, t.tunnel_ip, t.peer_tunnel_ip
  FROM profile_tunnel_ref ptr
  JOIN pqc_exchange_tunnels t ON t.id = ptr.tunnel_id
 WHERE ptr.profile_id = 23;
SELECT id, profile_id, priority, action, proto, src_ip, dst_ip,
       src_port, dst_port, method
  FROM ne_policies WHERE id = 1;
SELECT r.policy_id, r.key_id, k.status, k.local, k.remote
  FROM policy_pqc_ref r
  JOIN pqc_keys k ON k.key_id = r.key_id
 WHERE r.policy_id = 1;
