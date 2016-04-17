Inner-Cryptography
=======

Introduction
------------

This service provides methods to encrypt/decrypt datas, both in a simple way or with a stronger hash comparison.

Requirements
------------

* [Zend Framework 2](https://github.com/zendframework/zf2) (latest master)

Installation
------------

### Main Setup

#### By cloning project (not recommended)

1. Clone this project into your `./vendor/` directory.

#### With composer

    ```json
    "require": {
        "qbonaventure/Inner-Cryptography": "dev-master"
    }
    ```
    
#### Post installation

1. Enabling it in your `{application|module}.config.php`file.

    ```php
    <?php
    return array(
    	// ...
        'service_manager' => array(
	        'factories' => array(
	         	// ...
	        	'CryptographyInterface'	=> 'QBonaventure\InnerCryptography\ServiceFactory',	
	        ),
        ),
        // ...
    );
    ```

2. Copy config/mail.global.php.dist and config/mail.local.php.dist to your config directory
3. Remove the .dist extension from these files and fill in the blanks
