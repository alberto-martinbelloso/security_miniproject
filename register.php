<?php
//Getting ssas class
require_once("ssas.php");
$ssas = new Ssas();

//If a POST occured, try to authenticate
if(isset($_POST['username']) && isset($_POST['password'])){
    $result = $ssas -> createUser($_POST['username'],$_POST['password']);
    if($result === true){
        $result = $ssas -> login($_POST['username'],$_POST['password']);
        if($result === true) header("Location: index.php");
    }
}

//If the user is already logged in, redirect to index.php
if($ssas -> isUserLoggedIn()){
    header("Location: index.php");
    exit();
}
?>

<?php include 'header.php'; ?>

<div class="row">
    <div class="col-sm-6 col-sm-offset-3">
        <form action="register.php" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input 
                    id="username"
                    type="text" 
                    class="form-control"
                    name="username" 
                >
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input 
                    id="password"
                    type="password" 
                    class="form-control" 
                    name="password"
                >
            </div>
            <button type="submit" class="btn btn-success">Register</button>
        </form>

<?php if(isset($result)){ ?>
        </br>
        <div class="alert alert-danger" role="alert">
            <strong>Ups!</strong> <?php echo $result; ?>
        </div>
<?php } ?>

    </div>
</div>

<?php include 'footer.php'; ?>
