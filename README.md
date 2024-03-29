# SIDN-XML-WHOIS
A PHP Class to retrieve the Registrar WHOIS of .nl domains in a structured format.
With this class the different parts of the WHOIS can be retrieved and partly get reused,
thus removing parts of the WHOIS that you don't need for a particular process.

See the examples folder for the different use cases.

### Requirements
* Sockets and cURL
* SIDN registrar accreditation
* Your server firewall allowing outgoing connections
* Your server IPv4 (and if applicable IPv6) needs to added to the SIDN IP whitelist.

### To-do
* The old PDF documentation should be rewritten to Markdown or HTML documentation.

## Example
An example in it's most simple form:

```PHP
<?php
// include logic
if(!file_exists('src')) {
    chdir('../..'); // make examples executable from examples folder
}

foreach(glob('src/*.class.php') as $filename) {
    require($filename);
}

// execute
if(isset($_POST['domain']) && strlen($_POST['domain']) > 0) {
    $whois = new SidnXmlWhois('NL');
    $whois->whois($_POST['domain']);
    $whois->printWhois();
}
?>
```

Specific for IPv4 transport you would do this:

```PHP
<?php
if(isset($_POST['domain']) && strlen($_POST['domain']) > 0) {
    $whois = new SidnXmlWhois('NL');
    $whois->force_ipv4 = true;
    $whois->bindto_ipv4_address = '1.2.3.4';
    $whois->whois($_POST['domain']);
    $whois->printWhois();
}
?>
```

Specific for IPv6 transport you would use this:

```PHP
<?php
if(isset($_POST['domain']) && strlen($_POST['domain']) > 0) {
    $whois = new SidnXmlWhois('NL');
    $whois->force_ipv6 = true;
    $whois->bindto_ipv6_address = '1:2:3:4:5:6:7:8';
    $whois->whois($_POST['domain']);
    $whois->printWhois();
}
?>
```

And if choosing only specific parts of the WHOIS use this:

```PHP
<?php
if(isset($_POST['domain']) && strlen($_POST['domain']) > 0) {
    $whois = new SidnXmlWhois('NL');
    $whois->whois($_POST['domain']);
    
    // all optional
    $whois->parseContactRole('registrant');
    $whois->parseContactRole('admin');
    $whois->parseContactRole('tech');
    $whois->parseRegistrar();
    $whois->parseReseller();
    $whois->parseAbuseContact();
    $whois->parseHosts();
    
    // output
    $whois->printWhois();
}
?>
```

###### Author notes
* Updated in 2022 with some small improvements, making the library a final version.
* Initiated in 2010 and revised in 2012. Overhauled in 2018 to keep it working with PHP 7+ and added support for all new available functionality.
* Published on GitHub for easier community driven development.