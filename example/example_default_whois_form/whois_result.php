<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>XML-WHOIS Example integration</title>
</head>
<body>

<!--
	Style-less example of a simple WHOIS integration.
-->

<p>
	Click <a href="whois_form.html">here</a> to query for another WHOIS.<br />
</p>

<?php
// include logic
if(!file_exists('src')) {
    chdir('../..');
}

foreach(glob('src/*.class.php') as $filename) {
    require($filename);
}

// execute
if(isset($_POST['domain']) && strlen($_POST['domain']) > 0) {
	$whois = new SidnXmlWhois($_POST['domain']);
	$whois->print_whois(true);
}
?>

</body>
</html>