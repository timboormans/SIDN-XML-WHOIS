<?php

/**
 * A class to interface with the SIDN XML WHOIS.
 * This class creates objects to influence the structure of the output.
 *
 * @author Tim Boormans (Direct Web Solutions B.V.)
 * @license GPL
 */
class SidnXmlWhois {

    /* @var $xml_obj SimpleXMLElement */
    /* @var $maintainer SidnXmlWhoisDescription */
    /* @var $copyright SidnXmlWhoisDescription */

    // settable
    public $force_ipv4 = false;
    public $force_ipv6 = false;
    public $bindto_ipv4_address = '';
    public $bindto_ipv6_address = '';

    // gettable
    public $lang = 'NL'; // NL|EN
    public $domain = '';
	public $view = '';
	public $date = ''; // date of this request
	public $status = array('code' => '', 'lang' => '', 'format' => 'XML');
	public $registrar = array(); // exact 1
	public $registrant = array(); // exact 1
	public $admin = array(); // exact 1
	public $tech = array(); // 1 or more
	public $hosts = array(); // 0 or more
	public $registered = '';
	public $last_change = '';
	public $out_quarantine = '';
	public $maintainer = array(); // 0 or more
	public $copyright = array(); // 0 or more

    // private
	private $xml_obj;
    private $parse_strategy = 'all';
    private $parse_roles = array();
    private $parsed_contact_roles = array('registrant' => '', 'admin' => '', 'tech' => array()); // 0 or more
    private $parsed_host_roles = array();
    private $xml_str = '';
	private $log = array();

	public function __construct($lang = 'NL') {
        $this->lang = $lang;
	}

	public function whois($domain) {
	    // check data validity
        if(!preg_match('/^[a-z0-9-]{2,63}\.nl$/i', $domain)) {
            $this->quit("De domeinnaam '$domain' voldoet niet aan de door SIDN gestelde eisen.");
        }

        // init
        if(!in_array(strtoupper($this->lang), array('NL', 'EN'))) {
            $this->lang = 'NL';
        }
        $url = "http://rwhois.domain-registry.nl/whois?domain=".$domain."&format=xml&lang=".$this->lang;

        // execute
        if(ini_get("allow_url_fopen") == 1) {

            // use native PHP-functionality
            if($this->force_ipv4) {
                if($this->bindto_ipv4_address != '') {
                    $options = array('socket' => array('bindto' => $this->bindto_ipv4_address.':0'));
                } else {
                    $options = array('socket' => array('bindto' => '0:0'));
                }

            } elseif($this->force_ipv6) {
                if($this->bindto_ipv6_address != '') {
                    $options = array('socket' => array('bindto' => '['.$this->bindto_ipv6_address.']:0', 'ipv6_v6only' => true));
                } else {
                    $options = array('socket' => array('bindto' => '[0]:0', 'ipv6_v6only' => true));
                }
            }
            $context = stream_context_create($options);
            $this->xml_str = file_get_contents($url, null, $context);

        } elseif(function_exists('curl_init')) {

            // use cURL
            ini_set("user_agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1");
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_TIMEOUT, 5);
            curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
            $this->xml_str = curl_exec($curl);
            $response = curl_getinfo($curl);
            curl_close ($curl);

            // check the return header
            if($response['http_code'] != '200') {
                $this->quit("Cannot fetch the XML from SIDN. HTTP return code: ".$response['http_code'].".");
            }

        } else {
            // No wrapper found to handle the request
            $this->quit("Your server does not allow outbound connections. Enable sockets or cURL to proceed.");
        }
        if(!strpos($this->xml_str, '</whois-response>')) {
            $this->quit("Could not fetch the XML Whois from SIDN. Is your IP whitelisting configured correctly, both IPv4 and IPv6 (if applicable)?");
        }

        // modify whois result before processing
        $this->xml_str = str_replace("xmlns=", "xmlns:sidn=", $this->xml_str);
    }

    /**
     * Parse a specific contact role to $this result object
     *
     * @param $role
     */
    public function parseContactRole($role) {
	    $this->parse_strategy = 'selective';
	    $this->parse_roles[] = $role;

        // parse contacts per role instead of all contacts at once
        $this->parseRoles();

        // all contacts
        $contacts = $this->xml_obj->xpath('/whois-response/contact');
        foreach($contacts as $contact) {
            $d = array();
            $parse_contact = false;

            // contact id+view
            foreach($contact->attributes() as $key => $value) {
                if($key == "id") {
                    $d['id'] = trim((string)$value);
                } elseif($key == "view") {
                    $d['view'] = (string)$value;
                }
            }

            if($role == 'registrant' && $d['id'] == $this->parsed_contact_roles['registrant']) {
                // we search the registrant role with this id/handle
                $parse_contact = true;

            } elseif($role == 'admin' && $d['id'] == $this->parsed_contact_roles['admin']) {
                // we search the admin role with this id/handle
                $parse_contact = true;

            } elseif($role == 'tech' && in_array($d['id'], $this->parsed_contact_roles['tech'])) {
                // we search the tech role with this id/handle
                $parse_contact = true;
            }

            if($parse_contact) {
                // contact data
                $d['date'] = (string)$contact[0]->date;
                $d['name'] = (string)$contact[0]->name;
                $d['email'] = (string)$contact[0]->email;
                $d['voice'] = (string)$contact[0]->voice;
                if(isset($contact->address)) {
                    $d['street'] = (string)$contact->address->street;
                    $d['postal_code'] = (string)$contact->address->{"postal-code"};
                    $d['city'] = (string)$contact->address->city;
                    $d['cc'] = (string)$contact->address->{"country-code"};
                    $d['cn'] = (string)$contact->address->country; // country language
                } else {
                    $d['street'] = '';
                    $d['postal_code'] = '';
                    $d['city'] = '';
                    $d['cc'] = '';
                    $d['cn'] = '';
                }

                // create object and store as local variable
                if($this->parse_strategy == 'all' || in_array('registrant', $this->parse_roles)) {
                    if($d['id'] == $this->parsed_contact_roles['registrant']) {
                        $d['role'] = 'registrant';
                        $this->registrant = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                    }
                }

                if($this->parse_strategy == 'all' || in_array('admin', $this->parse_roles)) {
                    if($d['id'] == $this->parsed_contact_roles['admin']) {
                        $d['role'] = 'admin';
                        $this->admin = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                    }
                }

                if($this->parse_strategy == 'all' || in_array('tech', $this->parse_roles)) {
                    if(in_array($d['id'], $this->parsed_contact_roles['tech'])) {
                        $d['role'] = 'tech';
                        $this->tech[] = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                    }
                }

            }
        }
    }

    /**
     * Parse the registrar details to $this result object
     */
    public function parseRegistrar() {
        $this->parse_strategy = 'selective';

        if($this->xml_obj === null) {
            $this->reParseBaseWhoisElements();
        }

        // registrar details
        $res = array();
        $res['date'] = $this->xml_obj->xpath('/whois-response/registrar/date'); // date
        $res['name'] = $this->xml_obj->xpath('/whois-response/registrar/name'); // name
        $res['street'] = $this->xml_obj->xpath('/whois-response/registrar/address/street'); // street
        $res['postal_code'] = $this->xml_obj->xpath('/whois-response/registrar/address/postal-code'); // postal code
        $res['city'] = $this->xml_obj->xpath('/whois-response/registrar/address/city'); // city
        $res['cc'] = $this->xml_obj->xpath('/whois-response/registrar/address/country-code'); // country code
        $res['cl'] = $this->xml_obj->xpath('/whois-response/registrar/address/country'); // country lang

        $d = array();
        list( , $node) = each($res['date'][0]); $d['date'] = $node;
        list( , $node) = each($res['name'][0]); $d['name'] = $node;
        list( , $node) = each($res['street'][0]); $d['street'] = $node;
        list( , $node) = each($res['postal_code'][0]); $d['postal_code'] = $node;
        list( , $node) = each($res['city'][0]); $d['city'] = $node;
        list( , $node) = each($res['cc'][0]); $d['cc'] = $node;
        list( , $node) = each($res['cl'][0]); $d['cl'] = $node['lang'];
        $cn = (string)$res['cl'][0];

        $this->registrar = new SidnXmlWhoisRegistrar($d['date'], $d['name'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cl'], $cn);
    }

    /**
     * Parse the nameservers to $this result object
     */
    public function parseHosts() {
        $this->parse_strategy = 'selective';

        if($this->xml_obj === null) {
            $this->reParseBaseWhoisElements();
        }

        // determine host roles (unofficial)
        $res = $this->xml_obj->xpath('/whois-response/domain/nameserver');
        while(list( , $node) = each($res)) {
            $this->parsed_host_roles[trim((string)$node)] = 'in-zone';
            foreach($node->attributes() as $key => $value) {
                if($key == "in-zone") {
                    if($value == "true")
                        $this->parsed_host_roles[trim((string)$node)] = 'in-zone'; // true
                    else
                        $this->parsed_host_roles[trim((string)$node)] = 'out-zone'; // false
                }
            }
        }

        // all hosts (nameservers). Do not need to be coupled to the domainname (glue). See /whois-response/domain/nameserver for the other hosts.
        $nss = $this->xml_obj->xpath('/whois-response/nameserver');
        foreach($nss as $ns) {
            $d = array();
            $d['ipv4_address'] = array();
            $d['ipv6_address'] = array();

            // get hostname + details
            foreach($ns->attributes() as $key => $value) {
                if($key == "host")
                    $d['host'] = trim($value);
            }
            $d['date'] = (string)$ns->date;
            if(count($ns->{"ipv4-address"}) >= 1) {
                foreach($ns->{"ipv4-address"} as $ip) {
                    $d['ipv4_address'][] = (string)$ip; // 0 or more (10 maximum)
                }
            }
            if(count($ns->{"ipv6-address"}) >= 1) {
                foreach($ns->{"ipv6-address"} as $ip) {
                    $d['ipv6_address'][] = (string)$ip; // 0 or more (10 maximum)
                }
            }
            $d['zone'] = $this->parsed_host_roles[$d['host']];

            // store hosts as local variable
            $this->hosts[] = new SidnXmlWhoisHost($d['host'], $d['date'], $d['ipv4_address'], $d['ipv6_address'], $d['zone']);
        }

        // all missing nameservers
        foreach($this->parsed_host_roles as $hostname => $zone) {
            $found = false;
            for($i = 0; $i < count($this->hosts); $i++) {
                if($this->hosts[$i]->hostname == $hostname) {
                    $found = true;
                }
            }
            if(!$found) {
                $this->hosts[] = new SidnXmlWhoisHost($hostname, '', array(), array(), $zone);
            }
        }
    }

    /**
     * Output a displayable version of the composed WHOIS to the screen
     */
    public function printWhois() {
        print '<pre>'.$this->returnWhois().'</pre>';
    }

    /**
     * Get a plain text version of the WHOIS (based on what you have parsed)
     *
     * @return string
     */
    public function returnWhois() {

        $this->reParseBaseWhoisElements();

        $txt_whois = "";
        $txt_whois .= "Domain: ".$this->domain."\n";
        $txt_whois .= "Status: ".$this->status['code']."\n";
        $txt_whois .= "\n";

        // registrant
        if(count($this->registrant) > 0) {
            $txt_whois .= "Registrant:\n";
            $txt_whois .= "  ".$this->registrant->id."\n";
            $txt_whois .= "  ".$this->registrant->name."\n";
            $txt_whois .= "  ".$this->registrant->street."\n";
            $txt_whois .= "  ".$this->registrant->postal_code." ".$this->registrant->city."\n";
            $txt_whois .= "  ".$this->registrant->country_name."\n";
            $txt_whois .= "  ".$this->registrant->voice."\n";
            $txt_whois .= "  ".$this->registrant->email."\n";
            $txt_whois .= "\n";
        }

        // administrative contacts
        if(count($this->admin) > 0) {
            $txt_whois .= "Administrative contact:\n";
            $txt_whois .= "  ".$this->admin->id."\n";
            $txt_whois .= "  ".$this->admin->name."\n";
            $txt_whois .= "  ".$this->admin->voice."\n";
            $txt_whois .= "  ".$this->admin->email."\n";
            if(strlen($this->admin->street) > 0) {
                $txt_whois .= "  ".$this->admin->street."\n";
            }
            if(strlen($this->admin->postal_code.$this->admin->city) > 0) {
                $txt_whois .= "  ".$this->admin->postal_code." ".$this->admin->city."\n";
            }
            if(strlen($this->admin->country_name) > 0) {
                $txt_whois .= "  ".$this->admin->country_name."\n";
            }
            $txt_whois .= "\n";
        }

        // registrar
        if(count($this->registrar) > 0) {
            $txt_whois .= "Registrar:\n";
            $txt_whois .= "  ".$this->registrar->name."\n";
            $txt_whois .= "  ".$this->registrar->street."\n";
            $txt_whois .= "  ".$this->registrar->postal_code." ".$this->registrar->city."\n";
            $txt_whois .= "  ".$this->registrar->country_name."\n";
            $txt_whois .= "\n";
        }

        // technical contacts
        if(count($this->tech) > 0) {
            $txt_whois .= "Technical contact(s):\n";
        }

        for($i = 0; $i < count($this->tech); $i++) {
            $txt_whois .= "  ".$this->tech[$i]->id."\n";
            $txt_whois .= "  ".$this->tech[$i]->name."\n";
            if(strlen($this->tech[$i]->street) > 0) {
                $txt_whois .= "  ".$this->tech[$i]->street."\n";
            }

            if(strlen($this->tech[$i]->postal_code.$this->tech[$i]->city) > 0) {
                $txt_whois .= "  ".$this->tech[$i]->postal_code." ".$this->tech[$i]->city."\n";
            }

            if(strlen($this->tech[$i]->country_name) > 0) {
                $txt_whois .= "  ".$this->tech[$i]->country_name."\n";
            }

            $txt_whois .= "  ".$this->tech[$i]->voice."\n";
            $txt_whois .= "  ".$this->tech[$i]->email."\n";
            $txt_whois .= "  \n";
        }

        // nameservers
        if(count($this->hosts) > 0) {
            $txt_whois .= "Nameservers:\n";
        }

        for($i = 0; $i < count($this->hosts); $i++) {
            //ipv4 ips
            if(count($this->hosts[$i]->ipv4) > 0) {
                $ipv4 = "";
                foreach($this->hosts[$i]->ipv4 as $ip)
                    $ipv4 .= $ip." ";
                $txt_whois .= "  ".$this->hosts[$i]->hostname." ".$ipv4."\n";
            }

            // ipv6 ips
            if(count($this->hosts[$i]->ipv6) > 0) {
                $ipv6 = "";
                foreach($this->hosts[$i]->ipv6 as $ip)
                    $ipv6 .= $ip." ";
                $txt_whois .= "  ".$this->hosts[$i]->hostname." ".$ipv6."\n";
            }

            // no IPs, but there are hostnames
            if(count($this->hosts[$i]->ipv4) + count($this->hosts[$i]->ipv4) < 1) {
                $txt_whois .= "  ".$this->hosts[$i]->hostname."\n";
            }
        }

        if(count($this->hosts) > 0) {
            $txt_whois .= "  \n";
        }

        // properties
        $txt_whois .= "Creation Date: ".preg_replace('/Z.*/i', '', $this->registered)."\n";
        $txt_whois .= "Updated Date: ".preg_replace('/Z.*/i', '', $this->last_change)."\n";
        $txt_whois .= "\n";
        $txt_whois .= "Record maintained by: ".$this->maintainer->description."\n";
        $txt_whois .= "Printable whois by: Direct Web Solutions B.V.\n";
        $txt_whois .= "\n";
        $txt_whois .= "Copyright: ".$this->copyright->description."\n";

        return $txt_whois;
    }

    /**
     * Oldskool way of working with collections, return an array instead of an object
     *
     * @return array
     */
	public function returnWhoisAsArray() {

   		// export all techs
   		$tech_arr = array();
   		if(count($this->tech) > 0) {
   			for($i = 0; $i < count($this->tech); $i++) {
   				$tech_arr[] = array(
   				                     'id' => $this->tech[$i]->id
                                    ,'view' => $this->tech[$i]->view
                                    ,'date' => $this->tech[$i]->date
                                    ,'name' => $this->tech[$i]->name
                                    ,'email' => $this->tech[$i]->email
                                    ,'voice' => $this->tech[$i]->voice
                                    ,'has_address' => $this->tech[$i]->has_address
                                    ,'street' => $this->tech[$i]->street
                                    ,'postal_code' => $this->tech[$i]->postal_code
                                    ,'city' => $this->tech[$i]->city
                                    ,'country_code' => $this->tech[$i]->country_code
                                    ,'country_name' => $this->tech[$i]->country_name
                                    ,'contact_type' => $this->tech[$i]->contact_type
                                );
   			}
   		}

   		// export all hosts
   		$hosts_arr = array();
   		if(count($this->hosts) > 0) {
   			for($i = 0; $i < count($this->hosts); $i++) {
   				$hosts_arr[] = array(
   				                     'hostname' => $this->hosts[$i]->hostname
   									,'date' => $this->hosts[$i]->date
   									,'ipv4' => $this->hosts[$i]->ipv4
   									,'ipv6' => $this->hosts[$i]->ipv6
   									,'zone' => $this->hosts[$i]->zone
   									);
   			}
   		}

   		// put all together
   		$whois_array = array('domain' => $this->domain
   					,'view' => $this->view
   					,'date' => $this->date
   					,'status' => $this->status
   					,'registrar' => ((count($this->registrar) > 0) ?
   									array(
   									     'date' => $this->registrar->date
   										,'name' => $this->registrar->name
   										,'street' => $this->registrar->street
   										,'postal_code' => $this->registrar->postal_code
   										,'city' => $this->registrar->city
   										,'country_name' => $this->registrar->country_name
   										,'country_code' => $this->registrar->country_code
   										,'country_lang' => $this->registrar->country_lang
   									) : array()
   									)
   					,'registrant' => ((count($this->registrant) > 0) ?
   									array(
   									     'id' => $this->registrant->id
   										,'view' => $this->registrant->view
   										,'date' => $this->registrant->date
   										,'name' => $this->registrant->name
   										,'email' => $this->registrant->email
   										,'voice' => $this->registrant->voice
   										,'has_address' => $this->registrant->has_address
   										,'street' => $this->registrant->street
   										,'postal_code' => $this->registrant->postal_code
   										,'city' => $this->registrant->city
   										,'country_code' => $this->registrant->country_code
   										,'country_name' => $this->registrant->country_name
   										,'contact_type' => $this->registrant->contact_type
   									) : array()
   									)
   					,'admin' =>  ((count($this->admin) > 0) ?
   									array(
   									     'id' => $this->admin->id
   										,'view' => $this->admin->view
   										,'date' => $this->admin->date
   										,'name' => $this->admin->name
   										,'email' => $this->admin->email
   										,'voice' => $this->admin->voice
   										,'has_address' => $this->admin->has_address
   										,'street' => $this->admin->street
   										,'postal_code' => $this->admin->postal_code
   										,'city' => $this->admin->city
   										,'country_code' => $this->admin->country_code
   										,'country_name' => $this->admin->country_name
   										,'contact_type' => $this->admin->contact_type
   									) : array()
   									)
   					,'tech' => $tech_arr
   					,'hosts' => $hosts_arr
   					,'registered' => $this->registered
   					,'last_change' => $this->last_change
   					,'out_quarantine' => $this->out_quarantine
   					,'maintainer' => array(
   					                       'lang' => $this->maintainer->lang
   										  ,'format' => $this->maintainer->format
   										  ,'desc' => $this->maintainer->description
   									)
   					,'copyright' => array(
   					                        'lang' => $this->copyright->lang
   										  ,'format' => $this->copyright->format
   										  ,'desc' => $this->copyright->description
   									)
   		);

   		// return array with whois data
   		return $whois_array;
   	}

    private function reParseBaseWhoisElements() {
        // create an xml object
        $this->xml_obj = new SimpleXMLElement($this->xml_str);

        // domain + viewtype
        $res = $this->xml_obj->xpath('/whois-response/domain');
        list( , $node) = each($res[0]);
        $this->domain = $node['name'];
        $this->view = $node['view'];

        // date
        $res = $this->xml_obj->xpath('/whois-response/domain/date');
        list( , $node) = each($res[0]);
        $this->date = (string)$node;

        // domain status (whois status)
        $res = $this->xml_obj->xpath('/whois-response/domain/status/code');
        list( , $node) = each($res[0]);
        $this->status['code'] = $node;

        // domain status: lang & format
        $res = $this->xml_obj->xpath('/whois-response/domain/status/explain');
        list( , $node) = each($res[0]);
        $this->status['lang'] = $node['lang'];
        $this->status['format'] = strtoupper($node['format']);

        if($this->parse_strategy == 'all') { // parse all
            // contacts
            if(preg_match('/<contact/i', $this->xml_str)) {
                $this->parseContacts();
            }

            // registrar
            if(preg_match('/<registrar>/i', $this->xml_str)) {
                $this->parseRegistrar();
            }

            // hosts
            if(preg_match('/<nameserver/i', $this->xml_str)) {
                $this->parseHosts();
            }
        } // else these are parsed before this function was triggered

        // registered
        if(preg_match('/<registered>/i', $this->xml_str)) {
            $res = $this->xml_obj->xpath('/whois-response/domain/registered');
            list( , $node) = each($res[0]);
            $this->registered = (string)$node;
        }

        // last change
        if(preg_match('/<last-change>/i', $this->xml_str)) {
            $res = $this->xml_obj->xpath('/whois-response/domain/last-change');
            list( , $node) = each($res[0]);
            $this->last_change = (string)$node;
        }

        // out-of-quarantine date
        if($this->status['code'] == 'quarantine') {
            $res = $this->xml_obj->xpath('/whois-response/domain/status/domain-release-date');
            list( , $node) = each($res[0]);
            $this->out_quarantine = (string)$node;
        }

        // description maintainer
        $res = $this->xml_obj->xpath('/whois-response/signature/maintainer');
        list( , $node) = each($res[0]);
        $d = array();
        $d['lang'] = $node['lang'];
        $d['format'] = strtoupper($node['format']);
        $d['desc'] = (string)trim($res[0]);
        $this->maintainer = new SidnXmlWhoisDescription($d['lang'], $d['format'], $d['desc']);

        // description copyright
        $res = $this->xml_obj->xpath('/whois-response/signature/copyright');
        list( , $node) = each($res[0]);
        $d = array();
        $d['lang'] = $node['lang'];
        $d['format'] = strtoupper($node['format']);
        $d['desc'] = (string)trim($res[0]);
        $this->copyright = new SidnXmlWhoisDescription($d['lang'], $d['format'], $d['desc']);
    }
	
	private function parseContacts() {
		// parse ALL contacts only once
		$this->parseRoles();
		
		// all contacts
		$contacts = $this->xml_obj->xpath('/whois-response/contact');
		foreach($contacts as $contact) {
			$d = array();
			
			// contact id+view
			foreach($contact->attributes() as $key => $value) {
				if($key == "id") {
					$d['id'] = trim((string)$value);
				} elseif($key == "view") {
					$d['view'] = (string)$value;
				}
			}
			
			// contact address/data
			$d['date'] = (string)$contact[0]->date;
			$d['name'] = (string)$contact[0]->name;
			$d['email'] = (string)$contact[0]->email;
			$d['voice'] = (string)$contact[0]->voice;
			if(isset($contact->address)) {
				$d['street'] = (string)$contact->address->street;
				$d['postal_code'] = (string)$contact->address->{"postal-code"};
				$d['city'] = (string)$contact->address->city;
				$d['cc'] = (string)$contact->address->{"country-code"};
				$d['cn'] = (string)$contact->address->country; // country lang
			} else {
				$d['street'] = '';
				$d['postal_code'] = '';
				$d['city'] = '';
				$d['cc'] = '';
				$d['cn'] = '';
			}
			
			// create object and store as local variable
            if($this->parse_strategy == 'all' || in_array('registrant', $this->parse_roles)) {
                if($d['id'] == $this->parsed_contact_roles['registrant']) {
                    $d['role'] = 'registrant';
                    $this->registrant = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                }
            }

            if($this->parse_strategy == 'all' || in_array('admin', $this->parse_roles)) {
                if($d['id'] == $this->parsed_contact_roles['admin']) {
                    $d['role'] = 'admin';
                    $this->admin = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                }
            }

            if($this->parse_strategy == 'all' || in_array('tech', $this->parse_roles)) {
                if(in_array($d['id'], $this->parsed_contact_roles['tech'])) {
                    $d['role'] = 'tech';
                    $this->tech[] = new SidnXmlWhoisContact($d['id'], $d['view'], $d['date'], $d['name'], $d['email'], $d['voice'], $d['street'], $d['postal_code'], $d['city'], $d['cc'], $d['cn'], $d['role']);

                }
            }

		}
	}
	
	private function parseRoles() {

	    if($this->xml_obj === null) {
	        $this->reParseBaseWhoisElements();
        }

		// detect used roles
		$res = $this->xml_obj->xpath('/whois-response/domain/contact');
		while(list( , $node) = each($res)) {
			$id = trim((string)$node);
			foreach($node->attributes() as $key => $value) {
				if($key == "role") {
					$type = (string)$value;
					if($type == "registrant")
						$this->parsed_contact_roles['registrant'] = $id;
					elseif($type == "admin")
						$this->parsed_contact_roles['admin'] = $id;
					else
						$this->parsed_contact_roles['tech'][] = $id;
				}
			}
		}
	}

   	public function getLog() {
	    return $this->log;
    }

    private function log($msg) {
        $this->log[] = $msg;
    }

    private function quit($msg = '') {
        print $msg;
        exit();
    }
}