<?php

namespace Pimcore\Security\Hasher;

trait CheckPasswordBsiTrait
{
    public function isComplexPassword(string $password): bool
    {
        if (strlen($password) < 8 || strlen($password) > 12) {
            return false;
        }

        $uppercase = preg_match('/[A-Z]/', $password);
        $lowercase = preg_match('/[a-z]/', $password);
        $numbers = preg_match('/d/', $password);
        $specialCharacters = preg_match('/[^\w]/', $password);

        return $uppercase && $lowercase && $numbers && $specialCharacters;
    }

    public function isLongLessComplexPassword(string $password): bool
    {
        if (strlen($password) < 25) {
            return false;
        }

        $uppercase = preg_match('/[A-Z]/', $password);
        $lowercase = preg_match('/[a-z]/', $password);
        $numbers = preg_match('/d/', $password);
        $specialCharacters = preg_match('/[^\w]/', $password);

        $typesCount = count(array_filter([$uppercase, $lowercase, $numbers, $specialCharacters]));

        return $typesCount >= 2;
    }
}
