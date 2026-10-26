-- The finished file, so HEAD on a completed upload can report it.
ALTER TABLE uploads ADD COLUMN file_id TEXT REFERENCES files(id);
