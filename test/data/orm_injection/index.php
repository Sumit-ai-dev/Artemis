<?php
// Root index page: links to the vulnerable and non-vulnerable endpoints.
echo "<html><body>";
echo "<a href='/orm_injection.php?id=1'>ORM query (Doctrine)</a><br>";
echo "<a href='/nosql_injection.php?username=admin'>NoSQL login (MongoDB)</a><br>";
echo "<a href='/not_vuln.php?id=1'>Safe page</a><br>";
echo "</body></html>";
