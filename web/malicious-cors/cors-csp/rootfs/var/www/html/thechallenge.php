<?php
setrawcookie("dont_let_the_robots_see", "%2Ephp%2Eswp");

include "secret2.php";
include "secret1.php";
?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Challenge 7</title>
  </head>
  <body>
    <?php
    echo "<p>hello " . $_SESSION['role'] . "</p>";
    echo "<p>" . $msg . "</p>";
    ?>
  </body>
</html>
