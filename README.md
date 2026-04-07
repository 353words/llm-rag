## RAG : A Vulnerability Research Tool
++
title = "RAG : A Vulnerability Research Tool"
date = "FIXME"
tags = ["golang"]
categories = ["golang", "llm", "ai", "rag"]
url = "FIXME"
author = "mikit"
+++

### Introduction

In [the previous post][tools], you saw how you can use tools to add information to an LLM query.
In this post, we'll see another method of adding information to an LLM called [RAG][rag], or Retrieval-Augmented Generation. 

The idea of RAG is that you want the LLM to have access to information that wasn't available to it when it was initially trained.
You do it by storing documents in your own database along with their [embedding][embedding].
I won't go into the technical details of embedding, but think of it as a way to convert a piece of text into a vector.
The magic is that if two pieces of text have similar meaning, the vectors created by embedding them will also be similar.

In this post you'll use the [Go Vulnerability Database][vulndb] as our internal documents.

There are two different steps in this blog:
- Ingestion: Process the documents, create a vector and store them in a database
- Search: Retrieve relevant documents from the database to augment user query and ask LLM

Let's jump to the code and see how it's done.

### LLM Utilities

**Listing 1: llm.go**

```go
001 package main
002 
003 import (
004     "os"
005 
006     "github.com/tmc/langchaingo/embeddings"
007     "github.com/tmc/langchaingo/llms/openai"
008 )
009 
010 var baseURL string
011 
012 func init() {
013     baseURL = "http://localhost:8080/v1"
014     if host := os.Getenv("KRONK_WEB_API_HOST"); host != "" {
015         baseURL = host + "/v1"
016     }
017 }
018 
019 // NewLLM returns a connection to new LLM
020 func NewLLM(model string) (*openai.LLM, error) {
021     return openai.New(
022         openai.WithBaseURL(baseURL),
023         openai.WithToken("x"),
024         openai.WithModel(model),
025     )
026 }
027 
028 // NewEmbedder returns a new embedder.
029 func NewEmbedder() (embeddings.Embedder, error) {
030     llm, err := openai.New(
031         openai.WithBaseURL(baseURL),
032         openai.WithToken("x"),
033         openai.WithEmbeddingModel("Qwen3-Embedding-0.6B-Q8_0"),
034     )
035     if err != nil {
036         return nil, err
037     }
038 
039     return embeddings.NewEmbedder(llm)
040 }
```

Listing 1 shows the LLM utility functions.
On lines 12-17 `init` sets the URL for the [kronk][kronk] API.
`NewLLM` on lines 20-26 return a new OpenAI compatible connection to kronk. Since OpenAI API requires an API key we provide a mock one on line 23.
`NewEmbedder` on lines 29-40 return an LLM that can embed documents. We're using the small `Qwen3-Embedding-0` mode for that.


### Ingestion

In this step we read the data from the zip file, parse the JSON document and then create a vector embedding to insert into the database. Apart from the embedding vector, we store the CVE in text format as well as the ID. 

_Note: Knowing your own data and what people are going to query, you need to design the database schema. For example, if you have multi-tenant database, you can add a `user` column to make sure you query only document that the current user is allowed to read._

For this blog post I'll use [DuckDB](https://duckdb.org/) for its built-in vector support and a simple schema:


**Listing 2: Database Schema**

```sql
001 CREATE TABLE IF NOT EXISTS vulns (
002     id TEXT PRIMARY KEY,
003     content TEXT NOT NULL,
004     embedding FLOAT[1024]
005 );

```

Listing 2 shows the database schema. You use the `embedding` column to find out documents relevant to the user query.


**Listing 3: Vuln Struct**

```go
017 type Vuln struct {
018     ID        string
019     Published time.Time
020     Aliases   []string
021     Summary   string
022     Details   string
023     Affected  []json.RawMessage
024 }
025 
026 func (v Vuln) Package() string {
027     for _, a := range v.Affected {
028         var p struct {
029             Package struct {
030                 Name string
031             }
032         }
033         if err := json.Unmarshal(a, &p); err != nil {
034             continue
035         }
036 
037         return p.Package.Name
038     }
039 
040     return ""
041 }
042 
043 func (v Vuln) Content(full bool) string {
044     var buf strings.Builder
045 
046     if full {
047         fmt.Fprintln(&buf, "ID:", v.ID)
048         fmt.Fprintln(&buf, "Aliases:", strings.Join(v.Aliases, ","))
049         fmt.Fprintln(&buf, "Published:", v.Published)
050     }
051 
052     fmt.Fprintln(&buf, "Summary:", v.Summary)
053     fmt.Fprintln(&buf, "Details:", v.Details)
054     fmt.Fprintln(&buf, "Package:", v.Package())
055 
056     return buf.String()
057 }
```

Listing 3 shows the `Vuln` struct and its methods.
The `Vuln` struct on lines 17-24 matches the JSON document in the vulnerability zip file.
The `Package` method on lines 26-41 searches for the affected package using an anonymous struct trick to unmarshal only what we need from the complex JSON schema.
The `Content` method on lines 43-57 returns a string representation of the vulnerability. If `full` is `true` it include more fields—this is what's stored in the database for the LLM to read. For embedding (when `full` is `false`), we only use the `Summary`, `Details`, and `Package` fields to avoid adding "noise" like IDs and timestamps to the vector.


**Listing 4: decodeEntry`

```go
059 func decodeEntry(zf *zip.File) (Vuln, error) {
060     r, err := zf.Open()
061     if err != nil {
062         return Vuln{}, err
063     }
064     defer r.Close()
065 
066     dec := json.NewDecoder(r)
067 
068     var v Vuln
069     if err := dec.Decode(&v); err != nil {
070         return Vuln{}, err
071     }
072 
073     return v, nil
074 
075 }

```

Listing 4 shows `decodeEntry` that decodes an entry in the zip file.
On lines 60-64 you open the entry.
On line 66 you create a new JSON decoder and on lines 69-73 decode JSON and return it.

**Listing 5: ingest**

```go
076 var (
077     //go:embed sql/schema.sql
078     schemaSQL string
079 
080     //go:embed sql/insert.sql
081     insertSQL string
082 )
083 
084 func ingest(ctx context.Context, db *sql.DB) error {
085     // https://vuln.go.dev/vulndb.zip
086     r, err := zip.OpenReader("vulndb.zip")
087     if err != nil {
088         return err
089     }
090     defer r.Close()
091 
092     if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
093         return err
094     }
095 
096     em, err := NewEmbedder()
097     if err != nil {
098         return err
099     }
100 
101     tx, err := db.BeginTx(ctx, nil)
102     if err != nil {
103         return err
104     }
105     defer tx.Rollback()
106 
107     count, total, nErr := 0, len(r.File), 0
108 
109     for i, f := range r.File {
110         fmt.Printf("%d/%d\r", i+1, total)
111         if !strings.HasPrefix(f.Name, "ID/") {
112             continue
113         }
114 
115         count++
116         v, err := decodeEntry(f)
117         if err != nil {
118             slog.Error("decode", "error", err)
119             return err
120         }
121 
122         slog.Debug("ingest document", "id", v.ID)
123 
124         vec, err := em.EmbedQuery(ctx, v.Content(false))
125         if err != nil {
126             slog.Warn("embed", "id", v.ID, "error", err)
127             nErr++
128             continue
129         }
130 
131         if _, err := tx.ExecContext(ctx, insertSQL, v.ID, v.Content(true), vec); err != nil {
132             return err
133         }
134     }
135 
136     slog.Info("ingest", "total", total, "errors", nErr)
137     return tx.Commit()
138 }
```

Listing 5 shows the core logic of the `ingest` function.
On lines 76-82 you use the `embed` package to get the SQL for the schema and insertion.
On lines 86-90 you open the zip file.
On lines 92-94 you make sure the table exists in the database. In real world scenarios, the operations team creates the database and the table.
On lines 96-99 you create an embedder.
On lines 101-105 you create a new transaction. Working inside a transaction guarantees that either all the documents go into the database or none; it's a very good thing to have in data pipelines.
On line 107 you initialize some counters.
On line 109 you start looping on the zip file entries.
On line 110 you print the progress, the `\r` at the end means the same line is updated (vs a new line).
On lines 115-122 you decode the entry.
On lines 124-129 you use the LLM to create embedding for the documents.
On lines 131-134 you insert the embedding and the document to the database.
Finally on line 137 you commit the transaction.

Some design decisions:
- An individual document error does not halt the process but increases the number of errors. We prioritize completing the batch over perfect success.
- You embed and insert documents one-by-one. Both embedding and SQL have options to do batch processing that will speed up the process.

**Listing 6: sql/insert.sql**

```sql
001 INSERT INTO vulns (
002     id,
003     content,
004     embedding
005 ) VALUES (
006     ?,
007     ?,
008     ?::FLOAT[1024]
009 );
```

Listing 6 shows the insert SQL.
On lines 6-8 you use `?` as placeholder for the values. On line 8 you make sure the input parameter is casted to a vector of 1024 floats. You need to know the vector length the embedding process returns and update your code accordingly.

You can run `make ingest` to run this step.

### Searching

In the search part, you'll get a query from the user. First, you'll query the database for documents that are similar to the user query and then you'll ask the LLM the user query with these documents in the context.

**Listing 7: queryDB**

```go
014 //go:embed sql/search.sql
015 var searchSQL string
016 
017 func queryDB(ctx context.Context, db *sql.DB, query string, count int) ([]string, error) {
018     em, err := NewEmbedder()
019     if err != nil {
020         return nil, err
021     }
022 
023     vec, err := em.EmbedQuery(ctx, query)
024     if err != nil {
025         return nil, err
026     }
027 
028     rows, err := db.QueryContext(ctx, searchSQL, vec, count)
029     if err != nil {
030         return nil, err
031     }
032     defer rows.Close()
033 
034     var (
035         content    string
036         similarity float32
037         results    []string
038     )
039 
040     for rows.Next() {
041         if err := rows.Scan(&content, &similarity); err != nil {
042             return nil, err
043         }
044 
045         if similarity < 0.5 {
046             continue
047         }
048 
049         results = append(results, content)
050     }
051 
052     if err := rows.Err(); err != nil {
053         return nil, err
054     }
055 
056     return results, nil
057 }
```

Listing 7 shows `queryDB` which is the first part.
On line 15 you use `embed` to get the search SQL query.
On lines 18-21 you create a new embedder and on lines 23-27 you use it to embed the user query.
On lines 28 you query the database using the query embedding vector.
On lines 40-50 you iterate over the results, scanning the returned row to content and similarity and filtering out results with similarity less than 0.5. Note that similarity thresholds are highly dependent on the embedding model used.
Finally on line 56 you return the results.

**Listing 8: sql/search.sql**

```sql
001 SELECT
002     content,
003     array_cosine_similarity(embedding, ?::FLOAT[1024]) AS similarity 
004 FROM vulns
005 ORDER BY similarity DESC
006 LIMIT ?
007 ;
```

Listing 8 shows the search SQL.
On line 3 you use [cosine similarity][cosine] to measure the similarity between the user query and database document.
On line 5 your order by the similarity and one line 6 you limit the number of returned documents.

### Main

In `main.go` we tie everything up.

**Listing 9: main.go**

```go

017 func main() {
018     flag.BoolVar(&options.ingest, "ingest", false, "populate database from vulndb.zip")
019     flag.Usage = func() {
020         fmt.Fprintf(os.Stderr, "usage: %s [options] QUERY\n", path.Base(os.Args[0]))
021         flag.PrintDefaults()
022     }
023     flag.Parse()
024 
025     if os.Getenv("DEBUG") != "" {
026         h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
027             Level: slog.LevelDebug,
028         })
029         log := slog.New(h)
030         slog.SetDefault(log)
031     }
032 
033     db, err := sql.Open("duckdb", "vulns.ddb")
034     if err != nil {
035         fmt.Fprintf(os.Stderr, "error: %s\n", err)
036         os.Exit(1)
037     }
038     defer db.Close()
039 
040     ctx := context.TODO()
041 
042     if options.ingest {
043         if err := ingest(ctx, db); err != nil {
044             fmt.Fprintf(os.Stderr, "error: %s\n", err)
045             os.Exit(1)
046         }
047         return
048     }
049 
050     if flag.NArg() != 1 {
051         fmt.Fprintln(os.Stderr, "error: wrong number of arguments")
052         os.Exit(1)
053     }
054 
055     query := flag.Arg(0)
056     if err := search(ctx, db, query); err != nil {
057         fmt.Fprintf(os.Stderr, "error: %s\n", err)
058         os.Exit(1)
059     }
060 }
```

Listing 9 shows main.go.
On lines 18-23 you set the command line flags and parse them.
On lines 25-31 you set the log level to `DEBUG` if the `DEBUG` environment variable is set.
Since both ingest and search need a database connection, you create one on lines 33-38.
On line 40 you set the context to `context.TODO` signaling you're not sure yet about the timeout to use.
On line 42 you check if you `options.ingest` flag is set and if so you run ingestion on lines 43-47.
On lines 50-55 you get the user query from the command line and on lines 56-59 you call the search.

You can run a search example using `make search`:

```
$ make search
go run . 'what are three most common causes of errors in HTTP?'


Three most common causes of HTTP errors in the provided context:
1. **Resource exhaustion** due to improper handling of large JSON responses (e.g., in `github.com/cloudflare/cfrpki`).
2. **Denial of service (DoS)** via malicious chunk extensions in HTTP handlers (e.g., `net/http`).
3. **Improper access control** in CORS handling that bypasses the Same Origin Policy.
```

### Conclusion and Further Steps

In about 350 lines of Go code, we created a system that ingests data and search in it using embeddings and LLM.
Using RAG allows LLM to work with data that was not available to them when they were trained. 
The most common use case is data that's internal to the company.

In real scenarios you'll run ingestion on a schedule or when someone adds a new document.

One main area for improvement in the ingestion process is chunking.
Say you embed a whole book, if you add it as context to your query you'll fill up the context and will get bad results (if any).
You need to split long documents to meaningful chunks, where "meaningful" differs for the type of document.
For example, you'll split source code by functions, markdown files by headings and [more][chunking].

Another place where you can improve the code is enhancing the user query.
Most users write short queries, and you can ask an LLM to enhance the user query with more words to get better matches.
But, this adds another step to the search phase, which uses more tokens (money) and takes more time.

As an exercise, you can [grab the code][code] and implement both chunking and query enhancement ☺

What interesting uses did you find for RAGs? Drop me a line at miki@ardanlabs.com


[chunking]: https://www.datacamp.com/blog/chunking-strategies
[code]: https://github.com/353words/llm-rag
[cosine]: https://en.wikipedia.org/wiki/Cosine_similarity
[embedding]: https://en.wikipedia.org/wiki/Embedding_(machine_learning)
[kron]: https://www.kronkai.com/
[rag]: https://en.wikipedia.org/wiki/Retrieval-augmented_generation
[tools]: https://www.ardanlabs.com/blog/2026/03/using-tools-a-meeting-scheduler/
[vulndb]: https://vuln.go.dev/

