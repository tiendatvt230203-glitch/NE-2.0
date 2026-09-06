DROP TABLE IF EXISTS policy_pqc_ref CASCADE;
DROP TABLE IF EXISTS profile_tunnel_ref CASCADE;
DROP TABLE IF EXISTS profile_bridge_ref CASCADE;
DROP TABLE IF EXISTS bridge_interfaces CASCADE;
DROP TABLE IF EXISTS ne_policies CASCADE;
DROP TABLE IF EXISTS ne_wan CASCADE;
DROP TABLE IF EXISTS ne_lan CASCADE;
DROP TABLE IF EXISTS pqc_exchange_tunnels CASCADE;
DROP TABLE IF EXISTS pqc_keys CASCADE;
DROP TABLE IF EXISTS bridges CASCADE;
DROP TABLE IF EXISTS ne_profiles CASCADE;


-- ============================================================
-- CREATE TABLES
-- ============================================================

-- ------------------------------------------------------------
-- 1. ne_profiles
-- ------------------------------------------------------------
CREATE TABLE ne_profiles (
id SERIAL PRIMARY KEY,
name VARCHAR(255) NOT NULL,
description VARCHAR(80),
weight_enable BOOLEAN NOT NULL DEFAULT FALSE,
loss_enable BOOLEAN NOT NULL DEFAULT FALSE,
latency_enable BOOLEAN NOT NULL DEFAULT FALSE,
latency_duration INT DEFAULT NULL,
loss_duration INT DEFAULT NULL,
bridge_enable BOOLEAN NOT NULL DEFAULT FALSE,
tunnel_enable BOOLEAN NOT NULL DEFAULT FALSE,
created_at TIMESTAMP DEFAULT NOW(),
created_by VARCHAR(255),
updated_at TIMESTAMP DEFAULT NOW(),
updated_by VARCHAR(255)
);

-- ------------------------------------------------------------
-- 2. ne_wan
-- ------------------------------------------------------------
CREATE TABLE ne_wan (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
interface VARCHAR(255) NOT NULL,
profile_id INT NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
dst_ip VARCHAR(255),
weight INT CHECK (weight <= 100),
latency_ip VARCHAR(255),
latency INT,
latency_enable BOOLEAN NOT NULL DEFAULT FALSE,
loss_ip VARCHAR(255),
loss_percentage INT CHECK (loss_percentage <= 100),
loss_enable BOOLEAN NOT NULL DEFAULT FALSE
);

-- ------------------------------------------------------------
-- 3. ne_lan
-- ------------------------------------------------------------
CREATE TABLE ne_lan (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
interface VARCHAR(255) NOT NULL,
profile_id INT NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- 4. bridges
-- ------------------------------------------------------------
CREATE TABLE bridges (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
ifname VARCHAR(255) NOT NULL,
description TEXT,
created_at TIMESTAMP DEFAULT NOW(),
created_by VARCHAR(255) ,
updated_at TIMESTAMP DEFAULT NOW(),
updated_by VARCHAR(255)
);

-- ------------------------------------------------------------
-- 5. bridge_interfaces
-- ------------------------------------------------------------
CREATE TABLE bridge_interfaces (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
bridge_id UUID NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
ifname VARCHAR(255) NOT NULL,
tag VARCHAR(10) NOT NULL CHECK (tag IN ('WAN', 'LAN'))
);

-- ------------------------------------------------------------
-- 6. pqc_keys
-- ------------------------------------------------------------
CREATE TABLE pqc_keys (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
key_id VARCHAR(255) NOT NULL UNIQUE,
status VARCHAR(20) CHECK (status IN ('await', 'exchange', 'establish', 'failed')),
log VARCHAR(500),
local TEXT NOT NULL,
remote TEXT,
created_at TIMESTAMP DEFAULT NOW(),
created_by VARCHAR(255) ,
updated_at TIMESTAMP DEFAULT NOW(),
updated_by VARCHAR(255)
);

-- ------------------------------------------------------------
-- 7. pqc_exchange_tunnels
-- ------------------------------------------------------------
CREATE TABLE pqc_exchange_tunnels (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tunnel_name VARCHAR(255) NOT NULL,
mode VARCHAR(10) NOT NULL CHECK (mode IN ('server', 'client')),
tunnel_ip VARCHAR(255),
client_peer_public_ip VARCHAR(255),
client_peer_listen_port INT CHECK (client_peer_listen_port BETWEEN 1 AND 65535),
server_public_ip VARCHAR(255),
server_listen_port INT,
private_key TEXT,
public_key TEXT,
peer_public_key TEXT,
peer_tunnel_ip VARCHAR(255),
created_at TIMESTAMP DEFAULT NOW(),
created_by VARCHAR(255) ,
updated_at TIMESTAMP DEFAULT NOW(),
updated_by VARCHAR(255)
);

-- ------------------------------------------------------------
-- 8. ne_policies
-- ------------------------------------------------------------
CREATE TABLE ne_policies (
id SERIAL PRIMARY KEY,
profile_id INT REFERENCES ne_profiles(id) ON DELETE SET NULL,
priority INT NOT NULL,
action VARCHAR(10) NOT NULL CHECK (action IN ('L2', 'L3', 'L4', 'bypass')),
proto VARCHAR(10) CHECK (proto IN ('tcp', 'udp', 'icmp', 'ospf' , 'tcp/udp') OR proto IS NULL),
src_ip TEXT[],
dst_ip TEXT[],
src_port TEXT[],
dst_port TEXT[],
invert_src_ip BOOLEAN NOT NULL DEFAULT FALSE,
invert_dst_ip BOOLEAN NOT NULL DEFAULT FALSE,
method VARCHAR(30) CHECK (method IN ('aes-gcm-128','aes-gcm-256','aes-ctr-128','aes-ctr-256','pqc-gcm') OR method IS NULL),
encryption_key TEXT
);

-- ------------------------------------------------------------
-- 9. policy_pqc_ref (join: ne_policies <-> pqc_keys)
-- ------------------------------------------------------------
CREATE TABLE policy_pqc_ref (
policy_id INT NOT NULL REFERENCES ne_policies(id) ON DELETE CASCADE,
key_id VARCHAR(255) NOT NULL REFERENCES pqc_keys(key_id) ON DELETE CASCADE,
created_at TIMESTAMP,
PRIMARY KEY (policy_id, key_id)
);

-- ------------------------------------------------------------
-- 10. profile_tunnel_ref (join: ne_profiles <-> pqc_exchange_tunnels)
-- ------------------------------------------------------------
CREATE TABLE profile_tunnel_ref (
profile_id INT NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
tunnel_id UUID NOT NULL REFERENCES pqc_exchange_tunnels(id) ON DELETE CASCADE,
PRIMARY KEY (profile_id, tunnel_id)
);

-- ------------------------------------------------------------
-- 11. profile_bridge_ref (join: ne_profiles <-> bridges)
-- ------------------------------------------------------------
CREATE TABLE profile_bridge_ref (
profile_id INT NOT NULL REFERENCES ne_profiles(id) ON DELETE CASCADE,
bridge_id UUID NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
PRIMARY KEY (profile_id, bridge_id)
);