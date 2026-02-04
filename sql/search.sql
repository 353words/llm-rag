SELECT
    id,
    content,
	array_cosine_similarity(embedding, ?::FLOAT[1024]) AS similarity 
FROM vulns
ORDER BY similarity
LIMIT ?
;
