<?php

namespace App\Http\Controllers\Api\Auth;

use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Auth;
use App\User;
class LoginController extends Controller
{
    public function authenticate(Request $request)
    {

    	//grab credentials from the Request
        	$credentials = $request->only('email', 'password');
    		try {
            // attempt to verify the credentials and create a token for the user
	            if (! $token = JWTAuth::attempt($credentials)) {
	                return response()->json(['error' => 'invalid_credentials'], 401);
	            }
	        } catch (JWTException $e) {
	            // something went wrong whilst attempting to encode the token
	            return response()->json(['error' => 'could_not_create_token'], 500);
	        }

	        // all good so return the token
	        return response()->json(compact('token'));
       
    // if(Auth::attempt(['email'=>$request->input('email'),'password'=>$request->input('password')]))
    // {
    	

    // 	$user = User::first();
    // 	//$token  = JWTAuth::fromUser($user);
    // 	try{
    // 		if(!$token  = JWTAuth::fromUser($user))
    // 		{
    // 			return response()->json(['error'=>'invalid credentials'],401);
    // 		}
    // 	}catch(JWTException $e){
    // 		return response()->json(['error'=>'could_not_create_token']);
    // 	}
    // 	return response()->json($token);

    		 
    // }	
    // else{
    // 	return "invalid";
        
    // }
    }



 public function getAuthenticatedUser()
{
	$user =Auth::user();
	try {

		if (! $user = JWTAuth::parseToken()->authenticate()) {
			return response()->json(['user_not_found'], 404);
		}

	} catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

		return response()->json(['token_expired'], $e->getStatusCode());

	} catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

		return response()->json(['token_invalid'], $e->getStatusCode());

	} catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

		return response()->json(['token_absent'], $e->getStatusCode());

	}

	// the token is valid and we have found the user via the sub claim
	return response()->json(compact('user'));
}

}
