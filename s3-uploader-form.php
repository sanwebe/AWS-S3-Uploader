<?php
$access_key         = "iam-user-access-key"; //Access Key
$secret_key         = "iam-user-secret-key"; //Secret Key
$my_bucket          = "mybucket"; //bucket name
$region             = "us-east-1"; //bucket region
$success_redirect   = 'http://'. $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']; //URL to which the client is redirected upon success (currently self) 
$allowd_file_size   = "1048579"; //1 MB allowed Size

//dates
$short_date 		= gmdate('Ymd'); //short date
$iso_date 			= gmdate("Ymd\THis\Z"); //iso format date
$expiration_date 	= gmdate('Y-m-d\TG:i:s\Z', strtotime('+1 hours')); //policy expiration 1 hour from now

//POST Policy required in order to control what is allowed in the request
//For more info http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
$policy = utf8_encode(json_encode(array(
					'expiration' => $expiration_date,  
					'conditions' => array(
						array('acl' => 'public-read'),  
						array('bucket' => $my_bucket), 
						array('success_action_redirect' => $success_redirect),
						array('starts-with', '$key', ''),
						array('content-length-range', '1', $allowd_file_size), 
						array('x-amz-credential' => $access_key.'/'.$short_date.'/'.$region.'/s3/aws4_request'),
						array('x-amz-algorithm' => 'AWS4-HMAC-SHA256'),
						array('X-amz-date' => $iso_date)
						)))); 

//Signature calculation (AWS Signature Version 4)	
//For more info http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html	
$kDate = hash_hmac('sha256', $short_date, 'AWS4' . $secret_key, true);
$kRegion = hash_hmac('sha256', $region, $kDate, true);
$kService = hash_hmac('sha256', "s3", $kRegion, true);
$kSigning = hash_hmac('sha256', "aws4_request", $kService, true);
$signature = hash_hmac('sha256', base64_encode($policy), $kSigning);
?>
<!DOCTYPE HTML>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Aws S3 Direct File Uploader</title>
<style type="text/css">
.upload-wrap{
    width: 450px;
    margin: 60px auto;
    padding: 30px;
    background-color: #F3F3F3;
    overflow: hidden;
    border: 1px solid #ddd;
    text-align: center;
}
</style>
</head>
<body>
<div class="upload-wrap">
<form action="http://<?= $my_bucket ?>.s3.amazonaws.com/" method="post" enctype="multipart/form-data">
<input type="hidden" name="key" value="${filename}" />
<input type="hidden" name="acl" value="public-read" />
<input type="hidden" name="X-Amz-Credential" value="<?= $access_key; ?>/<?= $short_date; ?>/<?= $region; ?>/s3/aws4_request" />
<input type="hidden" name="X-Amz-Algorithm" value="AWS4-HMAC-SHA256" />
<input type="hidden" name="X-Amz-Date" value="<?=$iso_date ; ?>" />
<input type="hidden" name="Policy" value="<?=base64_encode($policy); ?>" />
<input type="hidden" name="X-Amz-Signature" value="<?=$signature ?>" />
<input type="hidden" name="success_action_redirect" value="<?= $success_redirect ?>" /> 
<input type="file" name="file" />
<input type="submit" value="Upload File" />
</form>
<?php
//After success redirection from AWS S3
if(isset($_GET["key"]))
{
	$filename = $_GET["key"];
	$ext = pathinfo($filename, PATHINFO_EXTENSION);
	if(in_array($ext, array("jpg", "png", "gif", "jpeg"))){
		echo '<hr />Image File Uploaded : <br /><img src="http://'.$my_bucket.'.s3.amazonaws.com/'.$_GET["key"].'" style="width:100%;" />';
	}else{
		echo '<hr />File Uploaded : <br /><a href="http://'.$my_bucket.'.s3.amazonaws.com/'.$_GET["key"].'">'.$filename.'</a>';
	}
}
?>
</div>
</body>
</html>
