<?php
// Simulates a NoSQL operator injection vulnerability.
// If the input contains a MongoDB operator pattern like [$ne], output a
// MongoServerError to simulate what a Node.js/Mongoose app would show.
$raw_query = $_SERVER['QUERY_STRING'];

if (strpos($raw_query, '[$ne]') !== false ||
    strpos($raw_query, '[$gt]') !== false ||
    strpos($raw_query, '$where') !== false) {
    echo 'MongoServerError: unknown top level operator: $ne';
    http_response_code(500);
} else {
    echo "<html><body>Login OK</body></html>";
}
