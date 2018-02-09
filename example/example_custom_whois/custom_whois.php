<?php
// include logic
if(!file_exists('src')) {
    chdir('../..');
}

foreach(glob('src/*.class.php') as $filename) {
    require($filename);
}

// application
$whois = new SidnXmlWhois('directwebsolutions.nl', 'NL', true);
$whois->parse_contact_role('registrant'); // add 'registrant' to the result set
$whois->parse_contact_role('admin'); // add 'admin' to the result set
$whois->parse_contact_role('tech'); // add 'tech' to the result set
$whois->parse_registrar(); // add 'registrar' to the result set
$whois->print_whois(true); // print the result set
