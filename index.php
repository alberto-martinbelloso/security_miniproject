<?php
require_once("ssas.php");
$ssas = new Ssas();
?>

<?php include 'header.php'; ?>
<?php if($ssas -> isUserLoggedIn()){ ?>
<?php $images = $ssas -> getImages(); ?>
<?php if(sizeof($images) > 0){ ?>
    <div class="card-columns">
<?php foreach($images as $image){ ?>
        <div class="card">
            <a href="image.php?id=<?php echo $image -> getId(); ?>">
                <img class="card-img-top" src="<?php echo $image -> getImage(); ?>"/>
            </a>
            <div class="card-footer">
                <span class="text-muted">posted by <?php echo $image -> getUser(); ?></span>
            </div>
        </div>
<?php } ?>
    </div>
<?php } else if (sizeof($images) == 0) { ?>
    <div class="container text-sm-center">
        <h1>You have nothing in your feed..</h1>
        <p class="lead"> Upload a picture to get started!</p>
    </div>
<?php } } else { ?>
<div id="carousel-example-generic" class="carousel slide" data-ride="carousel">
    <ol class="carousel-indicators">
        <li data-target="#carousel-example-generic" data-slide-to="0" class="active"></li>
        <li data-target="#carousel-example-generic" data-slide-to="1"></li>
        <li data-target="#carousel-example-generic" data-slide-to="2"></li>
    </ol>
    <div class="carousel-inner" role="listbox">
        <div class="carousel-item active">
            <img src="images/img1.jpg" alt="...">
            <div class="carousel-caption">
                <h3>Share you picture with the ones you love<h3>
            </div>
        </div>
        <div class="carousel-item">
            <img src="images/img2.jpg" alt="...">
        </div>
        <div class="carousel-item">
            <img src="images/img3.jpg" alt="...">
            <div class="carousel-caption">
                <h3>Register today!<h3>
            </div>
        </div>
    </div>
    <a class="left carousel-control" href="#carousel-example-generic" role="button" data-slide="prev">
        <span class="icon-prev" aria-hidden="true"></span>
        <span class="sr-only">Previous</span>
    </a>
    <a class="right carousel-control" href="#carousel-example-generic" role="button" data-slide="next">
        <span class="icon-next" aria-hidden="true"></span>
        <span class="sr-only">Next</span>
    </a>
</div>
<?php } ?>
<?php include 'footer.php'; ?>
