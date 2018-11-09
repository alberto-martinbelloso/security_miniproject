<?php
require_once("ssas.php");
$ssas = new Ssas();
$ssas -> authenticate();

?>

<!DOCTYPE html>
<html>
    <head>
        <!-- Required meta tags always come first -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta http-equiv="x-ua-compatible" content="ie=edge">

        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="http://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.2/css/bootstrap.min.css">
        <link rel="stylesheet" href="http://maxcdn.bootstrapcdn.com/font-awesome/4.5.0/css/font-awesome.min.css">
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="container">
            <nav class="navbar navbar-light bg-faded" role="navigation">
                <button class="navbar-toggler hidden-sm-up" type="button" data-toggle="collapse" data-target="#collapsing-navbar">
                    &#9776;
                </button>
                <span class="navbar-brand">ImageShare</span>
                <div class="collapse navbar-toggleable-xs" id="collapsing-navbar">
                    <ul class="nav navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link" href="index.php">Home</a>
                        </li>
    <?php if($ssas -> isUserLoggedIn()){ ?>
                        <li class="nav-item hidden-md-up">
                            <a class="nav-link" data-toggle="modal" data-target="#uploadModal">Upload</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="logout.php">Logout</a>
                        </li>

                        <form class="form-inline pull-xs-right hidden-sm-down" action="upload.php" method="post" enctype="multipart/form-data">
                            <input id="image-inline" type="file" class="form-control" name="image" accept="image/*" required onchange="update_filename('image-inline','filename-inline')" >
                            <div class="form-group has-primary">
                                <div class="input-group">
                                    <span class="input-group-btn">
                                        <button
                                            class="btn btn-primary-outline no-border-right" onclick="document.getElementById('image-inline').click();return false;">
                                            <i class="fa fa-file-image-o"></i>
                                        </button>
                                    </span>
                                    <input id="filename-inline" type="text" required class="form-control form-control-primary" placeholder="Select file">
                                    <span class="input-group-btn">
                                        <button type="submit" class="btn btn-primary-outline">Upload</button>
                                    </span>
                                </div>
                        </form>

    <?php } else { ?>
                         <li class="nav-item hidden-lg-up">
                            <a class="nav-link" href="login.php">Login</a>
                        </li>
                        <li class="nav-item hidden-lg-up">
                            <a class="nav-link" href="register.php">Register</a>
                        </li>
                        <form id="login-form" class="form-inline pull-xs-right hidden-md-down" method="post">
                            <div class="form-group">
                                <input placeholder="username" type="text" class="form-control" name="username">
                            </div>
                            <div class="form-group">
                                <input placeholder="password" type="password" class="form-control" name="password">
                            </div>
                            <button class="btn btn-success-outline" formaction="login.php">Login</button>
                            <button class="btn btn-success-outline" formaction="register.php">Register</button>
                        </form>
    <?php } ?>
                    </ul>
                </div>
    <?php if($ssas -> isUserLoggedIn()){ ?>
                <div class="modal fade" id="uploadModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-header">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                    <span aria-hidden="true">&times;</span>
                                </button>
                                <h4 class="modal-title" id="myModalLabel">Upload image</h4>
                            </div>
                            <form method="post" action="upload.php" enctype="multipart/form-data">
                                <div class="modal-body">
                                    <div class="form-group">
                                <input id="image" type="file" class="form-control" name="image" accept="image/*" required onchange="update_filename('image','filename')" >
                                    </div>
                                    <div class="form-group has-primary">
                                        <div class="input-group">
                                            <span class="input-group-btn">
                                                <button
                                                    class="btn btn-primary-outline no-border-right" onclick="document.getElementById('image').click();return false;">
                                                    <i class="fa fa-file-image-o"></i>
                                                </button>
                                            </span>
                                            <input id="filename" type="text" class="form-control form-control-primary" placeholder="Select file">
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                                    <button type="submit" class="btn btn-primary">Upload</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
    <?php } ?>
            </nav>
            <script type="text/javascript">
                function update_filename(src, target){
                    var fullPath = document.getElementById(src).value;
                    if (fullPath) {
                        var startIndex = (fullPath.indexOf('\\') >= 0 ? fullPath.lastIndexOf('\\') : fullPath.lastIndexOf('/'));
                        var filename = fullPath.substring(startIndex);
                        if (filename.indexOf('\\') === 0 || filename.indexOf('/') === 0) {
                            filename = filename.substring(1);
                        }
                        document.getElementById(target).value = filename;
                    }
                }
            </script>
