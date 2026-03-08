<?php
// Simulates a PHP application using Doctrine ORM where user input
// reaches a DQL query without sanitisation, leaking a Doctrine error.
$input = isset($_GET['id']) ? $_GET['id'] : '1';

// Naive string concatenation into a simulated DQL query (intentionally vulnerable)
// In a real Doctrine setup, string interpolation into DQL triggers a QueryException.
// We simulate the error output that Doctrine would produce.
$dql = "SELECT u FROM User u WHERE u.id = " . $input;

// Check if the input contains characters that would break a DQL query
if (preg_match('/[\'"]/', $input)) {
    // Simulate the Doctrine error that would be thrown
    echo "[Syntax Error] line 0, col 35: Error: Expected end of string, got '\"'";
    http_response_code(500);
} else {
    echo "<html><body>Query OK: user found</body></html>";
}
