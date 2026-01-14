-- Sequence and defined type
CREATE SEQUENCE IF NOT EXISTS users_id_seq;
CREATE SEQUENCE IF NOT EXISTS audit_id_seq;

-- Table Definition
CREATE TABLE IF NOT EXISTS users (
    "id" int4 NOT NULL DEFAULT nextval('users_id_seq'::regclass),
    "created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamptz DEFAULT CURRENT_TIMESTAMP,

    "email" varchar,
    "name" varchar,
    "whatsapp_number" varchar NOT NULL,
    "password_hash" varchar NOT NULL,
    "join_date" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "dojo" varchar,
    "date_of_birth" DATE,
    "rank" varchar,
    "last_grading_date" DATE,
 
    "role" varchar DEFAULT 'user',
    "consent_datastore" boolean DEFAULT false,
    "consent_marketing" boolean DEFAULT false,

    "medical_conditions" text,
    "emergency_contact_name" varchar,
    "emergency_contact_number" varchar,

    PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS audit (
    "id" int4 NOT NULL DEFAULT nextval('audit_id_seq'::regclass),
    "created_at" timestamptz DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamptz DEFAULT CURRENT_TIMESTAMP,

    "user_id" int4,
    "action" varchar,

    PRIMARY KEY ("id")
);

-- Indices
CREATE UNIQUE INDEX users_whatsapp_idx ON users USING btree (whatsapp_number);
CREATE UNIQUE INDEX users_email_idx ON users USING btree (email);
CREATE INDEX users_join_idx ON users USING btree (join_date);
CREATE INDEX audit_user_idx ON audit USING btree (user_id);