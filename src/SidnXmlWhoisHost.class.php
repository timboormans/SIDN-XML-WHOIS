<?php

/**
 * Class SidnXmlWhoisHost
 *
 * Host object for domain names
 */
class SidnXmlWhoisHost {

	public $hostname = '';
	public $date = ''; // date of this request
	public $ipv4 = array();
	public $ipv6 = array();
	public $zone = 'in-zone'; // in-zone / out-zone (whether the domain is published as part of the registry zone file)

	public function __construct($hostname, $date, $ipv4, $ipv6, $zone = 'in-zone') {
		// init
		$this->hostname = $hostname;
		$this->date = $date;
		$this->ipv4 = $ipv4;
		$this->ipv6 = $ipv6;
		if($zone == 'in-zone')
			$this->zone = 'in-zone';
		else
			$this->zone = 'out-zone';
	}

	public function get_all_ips() {
		return array_merge($this->ipv4, $this->ipv6);
	}
}