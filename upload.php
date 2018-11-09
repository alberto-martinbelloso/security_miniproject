<?php
require_once("ssas.php");
$ssas = new Ssas();

if(!$ssas -> isUserLoggedIn()){
    header("Location: index.php");
    echo "redicrect!";
    exit();
}

//If a POST occured, try to authenticate
if(isset($_FILES['image'])){
    $file_tmp = $_FILES['image']['tmp_name'];
    if($file_tmp != ""){
        $info = getimagesize($file_tmp);
        if (isset($info)) {
            if (($info[2] === IMAGETYPE_GIF) || ($info[2] === IMAGETYPE_JPEG) || ($info[2] === IMAGETYPE_PNG)) {
                if(filesize($file_tmp) / 1000 < 4096 ){
                    $image = 'data:' . $info['mime'] . ';base64,' . base64_encode(file_get_contents($file_tmp));
                    $result = $ssas -> uploadImage($image);
                    if($result){ header("Location: index.php"); exit(); }
                } else $result = "Images can't be more than 4 megabyte";
            } else $result = "The uploaded file was not an image";
        } else $result = "Info about the uploaded image could not be retrieved";
    } else $result = "Please select a file";
}

?>

<?php include 'header.php'; ?>
<?php if($ssas -> isUserLoggedIn()){ ?>
<div class="row">
    <div class="col-sm-8 col-sm-offset-2">
<?php if(isset($result)){ ?>
        </br>
        <div class="alert alert-danger" role="alert">
            <strong>Error!</strong> <?php echo $result; ?> 
        </div>
<?php } ?>
        <form method="post" action="upload.php" enctype="multipart/form-data">
            <div class="form-group">
                <input id="image-full" type="file" class="form-control" name="image" accept="image/*" required onchange="update_filename('image-full','filename-full')" >
            </div>
            <div class="form-group has-primary">
                <label>Please select an image:</label>
                <div class="input-group">
                    <span class="input-group-btn">
                        <button
                            class="btn btn-primary-outline no-border-right" onclick="document.getElementById('image-full').click();return false;">
                            <i class="fa fa-file-image-o"></i>
                        </button>
                    </span>
                    <input id="filename-full" type="text" class="form-control form-control-primary" placeholder="Select file">
                    <span class="input-group-btn">
                        <button type="submit" class="btn btn-primary">Upload</button>
                    </span>
                </div>
            </div>
        </form>
    </div>
</div>
<?php } ?>
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
<?php include 'footer.php'; ?>
