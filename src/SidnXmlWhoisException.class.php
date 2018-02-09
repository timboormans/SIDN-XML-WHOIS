<?php

/**
 * Class SidnXmlWhoisException
 *
 * Custom WHOIS exception for creating your own look and feel with error messages
 */
class SidnXmlWhoisException extends Exception {

    protected $message = '';
    protected $code = '';

    public function __construct($message, $code = 0, Exception $previous = null) {
        if($message == '')
            $message = 'An unknown error has encountered.';
        $this->message = 'SidnXmlException: '.$message;
        $this->code = $code;

        // make sure everything is assigned properly
        parent::__construct($message, $code);
        $this->_throw($message);
    }

    private function _throw($message) {
        print '<h1>WHOIS Exception:</h1>';
        print '<span style="color: red; font-size: 13pt;">'.$message.'</span>';
        exit();
    }
}