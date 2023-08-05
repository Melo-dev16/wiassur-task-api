<?php

namespace App\Controller;

use App\Entity\ApiToken;
use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\Persistence\ManagerRegistry;
use App\Service\AuthService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

class LoginController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['POST'])]
    public function login(Request $request, AuthService $auth, UserRepository $userRepository, ManagerRegistry $doctrine): Response
    {
        $data = json_decode($request->getContent(), true);

        $email = $data["email"];
        $password = $data["password"];

        if (is_null($email) || is_null($password)) {
            return new Response("No Email or Password", 400);
        }

        $user = $userRepository->findOneBy(['email' => $email]);

        if (!$user) {
            return new Response("No User Found", 400);
        }

        if (!$auth->verifyPassword($user, $password)) {
            return new Response("Password Invalid", 403);
        }

        //Rafraichir le token
        $user->setToken(bin2hex(openssl_random_pseudo_bytes(10)));

        $entityManager = $doctrine->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse([
            'id' => $user->getId(),
            "email" => $user->getEmail(),
            "roles" => $user->getRoles(),
            "firstname" => $user->getFirstname(),
            "lastname" => $user->getLastname(),
            "token" => $user->getToken()
        ]);
    }

    #[Route('/auto_login', name: 'app_auto_login', methods: ['POST'])]
    public function autoLogin(Request $request, AuthService $auth, UserRepository $userRepository, ManagerRegistry $doctrine): Response
    {
        $data = json_decode($request->getContent(), true);

        $email = $data["email"];
        $token = $data["token"];

        if (is_null($email) || is_null($token)) {
            return new Response("No Email or Token", 400);
        }

        $user = $userRepository->findOneBy(['email' => $email]);

        if (!$user) {
            return new Response("No User Found", 400);
        }

        if ($user->getToken() !== $token) {
            return new Response("Password Invalid", 403);
        }

        //Rafraichir le token
        $user->setToken(bin2hex(openssl_random_pseudo_bytes(10)));

        $entityManager = $doctrine->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse([
            'id' => $user->getId(),
            "email" => $user->getEmail(),
            "roles" => $user->getRoles(),
            "firstname" => $user->getFirstname(),
            "lastname" => $user->getLastname(),
            "token" => $user->getToken()
        ]);
    }

    #[Route('/signup', name: 'app_signup', methods: ['POST'])]
    public function signup(Request $request, UserRepository $userRepository, ManagerRegistry $doctrine): Response
    {
        $data = json_decode($request->getContent(), true);

        $email = $data["email"];
        $password = $data["password"];
        $firstname = $data["firstname"];
        $lastname = $data["lastname"];

        $withEmail = $userRepository->findOneBy(['email' => $email]);

        if ($withEmail) {
            return new Response("Adresse email non disponible !", 400);
        }

        $user = new User();
        $user->setEmail($email);
        $user->setPassword($password);
        $user->setFirstName($firstname);
        $user->setLastname($lastname);
        $user->setToken(bin2hex(openssl_random_pseudo_bytes(10)));

        $entityManager = $doctrine->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse([
            'id' => $user->getId(),
            "email" => $user->getEmail(),
            "roles" => $user->getRoles(),
            "firstname" => $user->getFirstname(),
            "lastname" => $user->getLastname(),
            "token" => $user->getToken()
        ]);
    }
}
