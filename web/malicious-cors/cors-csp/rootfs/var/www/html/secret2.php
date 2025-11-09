<?php
function monkeyCheckLink($l) {
  exec('node /myscript.js ' . escapeshellarg($l));
  return "the monkey is checkin out your link";
}
?>
