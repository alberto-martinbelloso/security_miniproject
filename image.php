<?php
require_once("ssas.php");
$ssas = new Ssas();

if(isset($_POST['share'])){ $share_result = $ssas -> shareImage($_GET["id"], $_POST['share']); }
if(isset($_GET["id"])) $image = $ssas -> getImage($_GET["id"]);
if(!isset($image)){
    header("Location: index.php");
    echo "redirect!";
    exit();
}
if(isset($_POST['comment'])){ $comment_result = $ssas -> comment($image -> getId(), $_POST['comment']); }
if(isset($_POST['remove_share'])){ $share_result = $ssas -> removeShare($image -> getId(), $_POST['remove_share']); }


?>

<?php include 'header.php'; ?>
<div class="row">
<div class="col-lg-8 col-lg-offset-2">
<div class="card">
    <img class="card-img-top" src="<?php echo $image -> getImage(); ?>"/>
    <div class="card-footer text-muted">
        posted by <?php echo $image -> getUser(); ?> ( <?php echo $image -> getAge() ?> ago )
<?php if($ssas -> getUid() == $image ->getOwnerId()){ ?>
<?php $sharedWith = $ssas -> sharedWith($image -> getId()); ?>
   <span style="float:right; margin-top:-2px;">
<?php if(sizeof($sharedWith) > 0){ ?>
        <span>
<?php foreach($sharedWith as $user) { ?>
            <a data-toggle="modal" data-target="#modalDelete<?php echo $user -> getId(); ?>"><span class="label label-default"><?php echo $user -> getName(); ?></span></a>
            <div class="modal fade" id="modalDelete<?php echo $user -> getId(); ?>" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-sm" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                            <h4 class="modal-title" id="myModalLabel">Stop sharing</h4>
                        </div>
                        <div class="modal-body">
                            Do you really want to remove <?php echo $user -> getName(); ?>
                        </div>
                        <div class="modal-footer">
                            <form method="post" action="image.php?id=<?php echo $image -> getId(); ?>">
                                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                                <button type="submit" name="remove_share" value="<?php echo $user -> getName()?>" class="btn btn-danger">Remove</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
<?php } ?>
        </span>
<?php } ?>
<?php $toShareWith = $ssas -> getUsersToShareWith($image -> getId()); ?>
<?php if(sizeof($toShareWith)){ ?>

        <span>
            <a data-toggle="modal" data-target="#shareModal"><span class="label label-primary">share <i class="fa fa-share"></i></span></a>
            <div class="modal fade" id="shareModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-sm" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                            <h4 class="modal-title" id="myModalLabel">Share with</h4>
                        </div>
                        <form method="post" action="image.php?id=<?php echo $image -> getId(); ?>">
                            <div class="modal-body">
                                <fieldset class="form-group">
                                    <label for="shareSelect">Share with</label>
                                    <select class="form-control" id="shareSelect" name="share">
                                        <?php foreach($toShareWith as $user) { ?> <option><?php echo $user -> getName(); ?> </option> <?php } ?>
                                    </select>
                                </fieldset>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                                <button type="submit" class="btn btn-primary">Share</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </span>
<?php } ?>
    </p>
<?php } ?>

    </div>
</div>
<?php foreach($ssas -> getComments($image -> getId()) as $comment){ ?>
<div class="card">
    <div class="card-block">
        <p class="card-text lead">
            <?php echo $comment -> getText(); ?></br>
        </p>
    </div>
    <div class="card-footer text-muted">
        posted by <?php echo $comment -> getUser(); ?> ( <?php echo $comment -> getAge() ?> ago )
    </div>
</div>
<?php } ?>
<div class="card">
    <div class="card-block">
        <p class="card-text">
<?php if(isset($comment_result) && !$comment_result){ ?>
            </br>
            <div class="alert alert-danger" role="alert">
                <strong>Ups!</strong> Something went wrong...
<?php } ?>
        <form method="post" action="image.php?id=<?php echo $image -> getId(); ?>">
                <fieldset class="form-group">
                    <textarea name="comment" class="form-control" rows="3" placeholder="Write a comment" required></textarea>
                </fieldset>
                <p class="text-xs-right">
                    <button type="submit" class="btn btn-primary">Comment</button>
                </p>
            </form>
        </p>
    </div>
</div>
</div>
</div>

<?php include 'footer.php'; ?>
