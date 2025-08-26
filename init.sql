-- Healthcare Platform Database Initialization
-- This script creates the database and initial setup

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE healthcare_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'healthcare_db')\gexec

-- Connect to the healthcare_db
\c healthcare_db;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_patients_patient_id ON patients(patient_id);
CREATE INDEX IF NOT EXISTS idx_records_record_id ON records(record_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
