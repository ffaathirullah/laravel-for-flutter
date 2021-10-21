<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    //
    public function Regiter(Request $request)
    {
        try {
            $request->validate([
                "name" => ["required", "string", "Max:255"],
                "username" => ["required", "string", "Max:255", "unique:users"],
                "email" => ["required", "string", "email", "Max:255", "unique:users"],
                "phone" => ["nullable", "string", "Max:255"],
                "password" => ["required", "string", new Password],
            ]);
            User::create([
                "name" => $request->name,
                "username" => $request->username,
                "email" => $request->email,
                "phone" => $request->phone,
                "password" => Hash::make($request->password),
            ]);
            $user = User::where("email", $request->email)->first();
            $tokenResult = $user->createToken("authToken")->plainTextToken;

            return ResponseFormatter::success([
                "access_token" => $tokenResult,
                "token_type" => "Bearer",
                "user" => $user,
            ], "User Register");
        } catch (Exception $error) {
            //throw $th;
            return ResponseFormatter::error([
                "message" => "Something Went Wrong",
                "error" => $error,
            ], "Authentication failed", 500);
        }
    }
    public function Login(Request $request)
    {
        try {
            //code...
            $request->validate([
                "email" => "email|required",
                "password" => "required",
            ]);

            $credential = request([
                "email",
                "password"
            ]);
            if (!Auth::attempt($credential)) {
                return ResponseFormatter::error([
                    "message" => "UnAuthorized"
                ], "Authentication Failed", 500);
            }
            $user = User::where("email", $request->email)->first();

            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception("Invalid Credential");
            }
            $tokenResult = $user->createToken("authToken")->plainTextToken;
            return ResponseFormatter::success([
                "access_token" => $tokenResult,
                "token_type" => "Bearer",
                "user" => $user
            ], "Authenticated");
        } catch (Exception $error) {
            //throw $th;
            return ResponseFormatter::error([
                "message" => "Something Went Wrong",
                "error" => $error
            ], "Authentication Failed", 500);
        }
    }
    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), "Data user profile berhasil diambil");
    }
}
