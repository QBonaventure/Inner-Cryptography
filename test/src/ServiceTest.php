<?php
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
    
    protected $config;
 
    public function setUp()
    {
//         $this->controllerManager = $this->getMockBuilder('Zend\Mvc\Controller\ControllerManager') 
//                                         ->disableOriginalConstructor()
//                                         ->getMock();
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
	
	public function testEncryptAndDecrypt() {
		$testString	= 'Hello World !';
		
		$this->serviceLocator->expects($this->at(0))
                     ->method('get')
                     ->with('config')
                     ->willReturn($this->config);
		$service	= $this->factory->createService($this->serviceLocator);
		
		$encryptedString	= $service->encrypt($testString, null, true);
		
		$decryptedString	= $service->decrypt($encryptedString, null, true);
		var_dump($encryptedString);
		var_dump($decryptedString);
		var_dump($testString);
// 		$this->assertEquals($testString, $decryptedString);
	}
}