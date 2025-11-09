<?php
session_start();

if(array_key_exists('_username', $_POST) and array_key_exists('_password', $_POST)) {
  $username = $_POST['_username'];
  $password = hash("sha512", $_POST['_password']);

  if($username === 'guest' and $password === 'b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c') {
    $_SESSION['role'] = $username;
    die;
  }

  if($username === 'admin' and $password === '78e090fdb53a46e8d8bdf61cc0b77e0b706806abd07ec41516abfdba983b14c7c94072c35071a539b65f5ae83d2b23f77876790a44dea7e90de85a9237ba8527') {
    $_SESSION['role'] = $username;
    header('location: /admin');
    die;
  }

  $_SESSION['role'] = 'invalid credentials';
  echo 'invalid credentials';
}

if(array_key_exists('_check_link', $_POST)) {
  $msg = monkeyCheckLink($_POST['_check_link']);
}
?>
