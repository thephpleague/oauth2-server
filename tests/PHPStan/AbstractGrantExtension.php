<?php
declare(strict_types = 1);

namespace LeagueTests\PHPStan;

use League\OAuth2\Server\Grant\AbstractGrant;
use PhpParser\Node\Expr\MethodCall;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\MethodReflection;
use PHPStan\Type\DynamicMethodReturnTypeExtension;
use PHPStan\Type\NullType;
use PHPStan\Type\StringType;
use PHPStan\Type\Type;
use PHPStan\Type\TypeCombinator;

final class AbstractGrantExtension implements DynamicMethodReturnTypeExtension
{
    public function getClass(): string
    {
        return AbstractGrant::class;
    }

    public function isMethodSupported(MethodReflection $methodReflection): bool
    {
        return in_array($methodReflection->getName(), [
            'getRequestParameter',
            'getQueryStringParameter',
            'getCookieParameter',
        ], true);
    }

    public function getTypeFromMethodCall(MethodReflection $methodReflection, MethodCall $methodCall, Scope $scope): Type
    {
        return TypeCombinator::union(...[
            new StringType(),
            isset($methodCall->args[2]) ? $scope->getType($methodCall->args[2]->value) : new NullType(),
        ]);
    }
}
