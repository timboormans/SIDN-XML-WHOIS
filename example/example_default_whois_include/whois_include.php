<?php
// include logic
if(!file_exists('src')) {
    chdir('../..');
}

foreach(glob('src/*.class.php') as $filename) {
    require($filename);
}

// init
$whois = new SidnXmlWhois('directwebsolutions.nl');

// Print the complete WHOIS-record
$whois->print_whois(true);

// Use the OBJECT to display/copy only needed information
/* @var SidnXmlWhoisContact $whois->registrant */
print "<br>Registrant: ".$whois->registrant->name;
print "<br>Registrar: ".$whois->registrar->name;

// Use an ARRAY with textstrings instead of object orientation
$whois_ARRAY = $whois->get_whois_array();
print '<br>Registrant: '.$whois_ARRAY['registrant']['name'];
