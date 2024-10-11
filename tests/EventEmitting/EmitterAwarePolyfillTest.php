<?php

declare(strict_types=1);

namespace LeagueTests\EventEmitting;

use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use PHPUnit\Framework\TestCase;

class EmitterAwarePolyfillTest extends TestCase
{
    public function testGetEmitter(): void
    {
        $emitterAwarePolyfill = new class () {
            use EmitterAwarePolyfill;
        };

        // automatically generated
        $emitter = $emitterAwarePolyfill->getEmitter();
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getEmitter(),
            'The emitter should be the same instance'
        );
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getEventDispatcher(),
            'The event dispatcher should be the same instance'
        );
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getListenerRegistry(),
            'The listener registry should be the same instance'
        );

        // manually set
        $emitter = new EventEmitter();
        $emitterAwarePolyfill->setEmitter($emitter);
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getEmitter(),
            'The emitter should be the same instance'
        );
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getEventDispatcher(),
            'The event dispatcher should be the same instance'
        );
        self::assertSame(
            $emitter,
            $emitterAwarePolyfill->getListenerRegistry(),
            'The listener registry should be the same instance'
        );
    }
}
