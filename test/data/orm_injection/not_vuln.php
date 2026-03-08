<?php
// A clean page that does not produce any ORM errors
// Used to verify the module does not produce false positives
$input = isset($_GET['id']) ? htmlspecialchars($_GET['id']) : '1';
echo "<html><body>Welcome! Showing item: " . $input . "</body></html>";
