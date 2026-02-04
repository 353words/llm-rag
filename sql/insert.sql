INSERT INTO vulns (
    id,
    content,
    embedding
) VALUES (
    ?,
    ?,
    ?::FLOAT[1024]
);
