-- Attach kedua DB
ATTACH DATABASE '/root/old.db' AS old;
ATTACH DATABASE '/root/new.db' AS new;

INSERT INTO new.inbounds (
  user_id, up, down, total, all_time, remark, enable, expiry_time,
  traffic_reset, last_traffic_reset_time, listen, port, protocol,
  settings, stream_settings, tag, sniffing
)
SELECT
  user_id, up, down, total, all_time, remark, enable, expiry_time,
  traffic_reset, last_traffic_reset_time, listen, port, protocol,
  settings, stream_settings, tag, sniffing
FROM old.inbounds oi
WHERE NOT EXISTS (
  SELECT 1 FROM new.inbounds ni WHERE ni.tag = oi.tag
);

WITH map AS (
  SELECT oi.id AS old_in_id, ni.id AS new_in_id, oi.tag
  FROM old.inbounds oi
  JOIN new.inbounds ni ON ni.tag = oi.tag
)
INSERT INTO new.client_traffics (
  inbound_id, enable, email, up, down, all_time, expiry_time, total, reset, last_online
)
SELECT
  m.new_in_id, oc.enable, oc.email, oc.up, oc.down, oc.all_time, oc.expiry_time, oc.total, oc.reset, oc.last_online
FROM old.client_traffics oc
JOIN map m ON m.old_in_id = oc.inbound_id
ON CONFLICT(email) DO UPDATE SET
  inbound_id = excluded.inbound_id,
  enable     = excluded.enable,
  up         = excluded.up,
  down       = excluded.down,
  all_time   = excluded.all_time,
  expiry_time= excluded.expiry_time,
  total      = excluded.total,
  reset      = excluded.reset,
  last_online= excluded.last_online;

INSERT INTO new.inbound_client_ips (client_email, ips)
SELECT client_email, ips
FROM old.inbound_client_ips
ON CONFLICT(client_email) DO UPDATE SET
  ips = excluded.ips;

INSERT INTO new.outbound_traffics (tag, up, down, total)
SELECT tag, up, down, total
FROM old.outbound_traffics
ON CONFLICT(tag) DO UPDATE SET
  up   = excluded.up,
  down = excluded.down,
  total= excluded.total;
