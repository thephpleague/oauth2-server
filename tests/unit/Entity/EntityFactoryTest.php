<?php


namespace LeagueTests\Entity;


use League\OAuth2\Server\Entity\EntityFactory;
use Mockery as m;

class EntityFactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \League\OAuth2\Server\Entity\EntityFactory
     */
    private $entityFactory;

    public function setUp()
    {
        $abstractServer = m::mock('League\OAuth2\Server\AbstractServer');
        $this->entityFactory = new EntityFactory($abstractServer);
    }

    public function testBuildAccessTokenEntity()
    {
        $accessTokenEntity = $this->entityFactory->buildAccessTokenEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\accessTokenInterface',$accessTokenEntity);
    }

    public function testBuildAuthCodeEntity()
    {
        $authCodeEntity = $this->entityFactory->buildAuthCodeEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\authCodeInterface',$authCodeEntity);
    }

    public function testBuildClientEntity()
    {
        $clientEntity = $this->entityFactory->buildClientEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\clientInterface',$clientEntity);
    }

    public function testBuildRefreshTokenEntity()
    {
        $refreshTokenEntity = $this->entityFactory->buildRefreshTokenEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\refreshTokenInterface',$refreshTokenEntity);
    }

    public function testBuildScopeEntity()
    {
        $scopeEntity = $this->entityFactory->buildScopeEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\scopeInterface',$scopeEntity);
    }

    public function testBuildSessionEntity()
    {
        $sessionEntity = $this->entityFactory->buildSessionEntity();
        $this->assertInstanceOf('League\OAuth2\Server\Entity\sessionInterface',$sessionEntity);
    }

    public function tearDown()
    {
        m::close();
    }
}
 