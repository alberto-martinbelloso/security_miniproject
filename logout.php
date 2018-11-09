<?php
require_once("ssas.php");
$ssas = new Ssas();
$ssas -> logout();
header("Location: index.php");
?>
