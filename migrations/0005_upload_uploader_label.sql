-- Uploader's PIN/token label on in-progress uploads, so folder listings can show
-- "Uploading… from Volunteers" before the file exists. Rows from before this stay NULL.
ALTER TABLE uploads ADD COLUMN uploaded_by TEXT;
CREATE INDEX uploads_folder_active ON uploads(folder_id) WHERE status = 'active';
