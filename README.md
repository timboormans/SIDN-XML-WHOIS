# SIDN-XML-WHOIS
A PHP Class to retrieve the Registrar WHOIS of .nl domains in a structured format.
With this class the different parts of the WHOIS can be retrieved and partly get reused,
thus removing parts of the WHOIS that you don't need for a particular process.

See the examples folder for the different use cases.

### Requirements
* Sockets or cURL
* SIDN registrar accreditation
* Your server firewall allowing outgoing connections
* Your server IPv4 (and if applicable IPv6) need to added to the SIDN IP whitelist.

### Notes
The script is still working great, but needs some maintenance to cope support new functionality as released at the registry:
* Reseller support should be added
* DNSSEC support should be added
* Old pdf documentation should be rewritten to HTML documentation

## Example
An example in it's most simple form:

```PHP
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
```

###### Author notes
* Originally created in 2010 and revised in 2012.
* Published on GitHub for easier community driven development.