package com.sushil.controller;

import com.sushil.exception.TokenRefreshException;
import com.sushil.models.ERole;
import com.sushil.models.RefreshToken;
import com.sushil.models.Role;
import com.sushil.models.User;
import com.sushil.repositories.RoleRepository;
import com.sushil.repositories.UserRepository;
import com.sushil.security.jwt.JwtUtils;
import com.sushil.security.jwt.payloads.request.ForgetPasswordRequest;
import com.sushil.security.jwt.payloads.request.LoginRequest;
import com.sushil.security.jwt.payloads.request.SignupRequest;
import com.sushil.security.jwt.payloads.request.TokenRefreshRequest;
import com.sushil.security.jwt.payloads.response.ApiResponse;
import com.sushil.security.jwt.payloads.response.JwtResponse;
import com.sushil.security.jwt.payloads.response.MessageResponse;
import com.sushil.security.jwt.payloads.response.TokenRefreshResponse;
import com.sushil.security.services.RefreshTokenService;
import com.sushil.security.services.UserDetailsImpl;
import com.sushil.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*",maxAge = 36000)
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        if (roles.contains("ROLE_ADMIN")){
            return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(),userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
        }else if (roles.contains(("ROLE_MODERATOR"))){
            return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(),userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
        }else if (roles.contains("ROLE_USER")){
            return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(),userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
        }else {
            throw new RuntimeException("User role not authorized");
        }

       // return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(),userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
        //return null;

    }
    @PostMapping("/signup")
    public ResponseEntity<?> doRegistration(@RequestBody SignupRequest signupRequest){
        if (userRepository.existsByUsername(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Username: is already taken: {}"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageResponse("Email: is already taken!: {}"));
        }

        //TODO: Create New/Fresh user.
        User user = new User(signupRequest.getUsername(),signupRequest.getEmail(),encoder.encode(signupRequest.getPassword()),signupRequest.getMobileNo());
        Set<String> strRoles=signupRequest.getRole();
        Set<Role>  roles = new HashSet<>();
        if (strRoles==null){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(()-> new RuntimeException("Error: Role is not found. {}"));
            roles.add(userRole);
        }
        else {
            strRoles.forEach(role->{
                switch (role){
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(()->new RuntimeException("Error: Admin Role is not found. {}"));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(()->new RuntimeException("Error: Mod Role is not found. {}"));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(()-> new RuntimeException("Error: User Role os not found. {}"));
                        roles.add(userRole);

                }
            });

        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("Registration successfull.! "));

    }
    @PostMapping("/refreshToken")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request){
        String requestRefreshToken=request.getRefreshToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user->{
                    String token=jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token,requestRefreshToken));

                }).orElseThrow(()-> new TokenRefreshException(requestRefreshToken,"Refresh Token is not in database. {}"));
    }
    //TODO: Signout needs to complete the logic...
    @PostMapping("/signout")
    public ResponseEntity<?> logout(){
        UserDetailsImpl userDetails = (UserDetailsImpl)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId=userDetails.getId();
        refreshTokenService.deleteByUserId(userId);
        return ResponseEntity.ok(new MessageResponse("Log out successful.!"));
    }

    //TODO: Complete the code for forget password api.also generate 4 digit otp and send it on mobiel number for verification..
    @PostMapping("/forget-password")
    public ResponseEntity<?> forgetPassword(@RequestBody ForgetPasswordRequest forgetPasswordRequest){
        Optional<User> userOptional=userRepository.findByEmail(forgetPasswordRequest.getEmail());
        if (!userOptional.isPresent()){
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: User not found with email: "+forgetPasswordRequest.getEmail()));

        }
        else {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
    }
   //TODO : OTP is coming in console..
    @PostMapping("/generate-otp")
    public ResponseEntity<?> generateOtp(@RequestParam String mobileNo){
        try{
            userDetailsService.generateOtp(mobileNo);
            return ResponseEntity.ok(new ApiResponse(true,"OTP Generated successfully",null));
        }catch (Exception e){
            return ResponseEntity.badRequest().body(new ApiResponse(false,"Failed to generate OTP",null));
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
        // return ResponseEntity.ok().build();
    }

    @PostMapping("/signin/admin")
    public ResponseEntity<?> authenticateAdmin(@RequestBody LoginRequest loginRequest){
        Authentication authentication=authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        List<String> roles=authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        

        if (!roles.contains("ROLE_ADMIN")){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: You are Not Authorized to access this resource."));
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails=(UserDetailsImpl) authentication.getPrincipal();
        String jwt=jwtUtils.generateJwtToken(userDetails);
       
        return ResponseEntity.ok(new JwtResponse(jwt,null,
                userDetails.getId(),userDetails.getUsername(),userDetails.getEmail(),new ArrayList<>(roles)));

    }

}
