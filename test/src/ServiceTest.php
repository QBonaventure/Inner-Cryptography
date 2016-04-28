<?php
/**
 * @author	Quentin Bonaventure
 * @link    https://github.com/QBonaventure/Inner-Cryptography for the canonical source repository
 * @license New BSD License
 */

namespace InnerCryptographyTest;

use QBonaventure\InnerCryptography\ServiceFactory;
use InnerCryptographyTest\Bootstrap;


class TransportFactoryTest extends \PHPUnit_Framework_TestCase {
    
    /** @var ServiceFactory */
    protected $factory;
 
    /** @var ServiceLocatorInterface */
    protected $serviceLocator;
 
    /** @var \Zend\Mvc\Controller\ControllerManager */
    protected $controllerManager;
    
	/** @var array */
    protected $config;
 
    public function setUp()
    {
        $this->serviceLocator    = $this->getMock('Zend\ServiceManager\ServiceLocatorInterface');
        $this->factory	= new ServiceFactory();
        $this->config	= Bootstrap::getConfig();
    }
	
	public function testKeyNotConfiguredRaiseException() {
		$this->setExpectedException('InvalidArgumentException');
		$config	= $this->config;
		$config['cryptography']['key']	= null;

		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($config);
		$service	= $this->factory->createService($this->serviceLocator);
	}
	
	public function testIVNotConfiguredRaiseException() {
		$this->setExpectedException('InvalidArgumentException');
		$config	= $this->config;
		$config['cryptography']['iv']	= null;

		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($config);
		$service	= $this->factory->createService($this->serviceLocator);
	}
	
	public function testWeakEncryptAndDecrypt() {
		$testString	= 'Hello World !';
		
		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($this->config);
		$service	= $this->factory->createService($this->serviceLocator);
		
		$encryptedString	= $service->weakEncrypt($testString, null, true);
		
		$decryptedString	= $service->weakDecrypt($encryptedString, null, true);

		$this->assertEquals($testString, $decryptedString);
	}
	
	public function testStrongEncryptAndDecrypt() {
		$testString	= 'Hello World !';
		
		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($this->config);
		$service	= $this->factory->createService($this->serviceLocator);
		
		$encryptedString	= $service->encrypt($testString, null);

		$decryptedString	= $service->decrypt($encryptedString, null);

		$this->assertEquals($testString, $decryptedString);
	}
	
	public function testStrongEncryptAndDecryptWithBase64Encode() {
		$testString	= 'Hello World !';
		
		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($this->config);
		$service	= $this->factory->createService($this->serviceLocator);
		
		$encryptedString	= $service->encrypt($testString, null, true);

		$decryptedString	= $service->decrypt($encryptedString, null, true);

		$this->assertEquals($testString, $decryptedString);
	}
	
	public function testStrongEncryptAndDecryptWithProvidedKey() {
		$testString	= 'Hello World !';
		$testkey	= '123456789abcdef';
		
		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($this->config);
		$service	= $this->factory->createService($this->serviceLocator);
		
		$encryptedString	= $service->encrypt($testString, $testkey);

		$decryptedString	= $service->decrypt($encryptedString, $testkey);

		$this->assertEquals($testString, $decryptedString);
	}
}