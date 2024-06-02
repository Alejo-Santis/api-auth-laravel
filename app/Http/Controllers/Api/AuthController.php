<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // Validate data
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed'
        ]);
        // Create user
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();
        // Api response
        return response(["message" => "User register succesfully", "data" => $user], Response::HTTP_CREATED);
    }

    public function login(Request $request)
    {
        // Validate credentials
        $credentials = $request->validate([
            'email' =>'required|email',
            'password' => 'required'
        ]);

        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('token')->plainTextToken;
            $cookie = cookie('cookie_token', $token, 60 * 24);
            return response(["token" => $token], Response::HTTP_OK)->withoutCookie($cookie);
        } else {
            return response(["message" => "Invalid credentials"], Response::HTTP_UNAUTHORIZED);
        }

    }

    public function userProfile(Request $request)
    {
        return response()->json([
            "message" => "User profile",
            "userData" => Auth::user()
        ], Response::HTTP_OK);
    }

    public function logout()
    {
        $cookie = Cookie::forget('cookie_token');
        return response([
            "message" => "Log out successfully",
        ], Response::HTTP_OK)->withCookie($cookie);
    }

    public function allUsers()
    {
        $users = User::all();
        return response()->json([
            "users" => $users
        ], Response::HTTP_OK);
    }
}
