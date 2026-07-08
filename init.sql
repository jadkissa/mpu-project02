-- init.sql
-- Set timezone for the session
SET TIMEZONE = 'Asia/Damascus';

CREATE SEQUENCE IF NOT EXISTS event_cid_seq START 1;

CREATE TABLE IF NOT EXISTS event (
    sid             INT NOT NULL,
    cid             INT NOT NULL DEFAULT nextval('event_cid_seq'),
    signature       TEXT,
    signature_gen   INT,
    signature_id    INT,
    signature_rev   INT,
    timestamp       TIMESTAMPTZ NOT NULL,
    ip_src          INET,
    ip_dst          INET,
    layer4_sport    INT,
    layer4_dport    INT,
    ip_proto        INT,
    priority        INT,
    class_id        INT,
    PRIMARY KEY (sid, cid)
);

CREATE TABLE IF NOT EXISTS sensor (
    sid         SERIAL PRIMARY KEY,
    hostname    TEXT,
    interface   TEXT,
    filter      TEXT
);

CREATE TABLE IF NOT EXISTS signature (
    sig_id          SERIAL PRIMARY KEY,
    sig_name        TEXT,
    sig_class_id    INT,
    sig_priority    INT,
    sig_rev         INT,
    sig_sid         INT UNIQUE
);

CREATE TABLE IF NOT EXISTS statistics (
    id                  SERIAL PRIMARY KEY,
    total_snort_alerts  INT DEFAULT 0,
    high_threats        INT DEFAULT 0,
    medium_threats      INT DEFAULT 0,
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Set database timezone to Damascus
ALTER DATABASE mpu_db SET timezone TO 'Asia/Damascus';

INSERT INTO sensor (sid, hostname, interface, filter)
VALUES (1, 'snort-sensor', 'eth0', NULL)
ON CONFLICT (sid) DO NOTHING;

INSERT INTO statistics (id, total_snort_alerts, high_threats, medium_threats)
VALUES (1, 0, 0, 0)
ON CONFLICT (id) DO NOTHING;