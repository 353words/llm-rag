CREATE TABLE IF NOT EXISTS vulns (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding FLOAT[1024]
);
