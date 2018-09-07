<?php
// include logic
if(!file_exists('src')) {
    chdir('../..');
}

foreach(glob('src/*.class.php') as $filename) {
    require($filename);
}

// application
$whois = new SidnXmlWhois('NL');
$whois->parseContactRole('registrant'); // add 'registrant' to the result set
$whois->parseContactRole('admin'); // add 'admin' to the result set
$whois->parseContactRole('tech'); // add 'tech' to the result set
$whois->parseRegistrar(); // add 'registrar' to the result set
$whois->parseReseller(); // add 'reseller' to the result set
$whois->parseAbuseContact(); // add 'abuse contact' to the result set
$whois->printWhois(); // print the result set
