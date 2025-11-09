<?php session_start(); ?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Challenge 7</title>
  </head>
  <body>
    <h1>Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource. Allowed-Origins: localhost</h1>
    <?php
    if($_SESSION['role'] === 'guest') {
      echo '<p>You got to the admin page... as a guest. Womp womp.</p>';
    } else if($_SESSION['role'] === 'admin') {
      echo '<p>Welcome to the admin page. This time you\'re an admin.</p>';
      echo '<p>But that\'s not the point of this challenge. Try again</p>';
    } else {
      echo '<img width="640" height="360" src="https://i.kym-cdn.com/entries/icons/original/000/007/423/RageFace.jpg">';
    }
    ?>
  </body>
</html>
