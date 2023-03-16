package com.DemoSecurity.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.DemoSecurity.Repository.RoleRepository;
import com.DemoSecurity.Repository.UserRepository;
import com.DemoSecurity.exception.AppException;
import com.DemoSecurity.request.LoginRequest;
import com.DemoSecurity.request.SignUpRequest;
import com.DemoSecurity.responce.ApiResponse;
import com.DemoSecurity.responce.DetailRequest;
import com.DemoSecurity.responce.JwtAuthenticationResponse;
import com.DemoSecurity.security.JwtTokenProvider;
import com.DemoSecurity.security.UserPrincipal;
import com.DemoSecurity.table.Role;
import com.DemoSecurity.table.RoleName;
import com.DemoSecurity.table.User;


import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider tokenProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    @SuppressWarnings("unchecked")
	@PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "Username is already taken!"),
                    HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email Address already in use!"),
                    HttpStatus.BAD_REQUEST);
        }

        // Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new AppException("User Role not set."));

        user.setRoles(Collections.singleton(userRole));

        User result = userRepository.save(user);



        return ResponseEntity.ok().body(new ApiResponse(true, "User registered successfully"));
    }
    
    
    @GetMapping("/info")
    public ResponseEntity<?> userInfo(){
    	
    		UserPrincipal user = (UserPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    		DetailRequest detailRequest =new DetailRequest();
    		detailRequest.setEmail(user.getEmail());
    		detailRequest.setId(user.getId());
    		detailRequest.setName(user.getName());
    		detailRequest.setUsername(user.getUsername());
		
    		 return ResponseEntity.ok(detailRequest);
    }
    
    
    
    
   @GetMapping("/nft")
   public ResponseEntity<?> nft(){
	  Map<String, Object> map = new HashMap<>();
	  
//	  File folder = new File("C:\\Users\\LENOVO\\Downloads\\json_axo");
//	  File[] listOfFiles = folder.listFiles();
//
//	  System.out.println(listOfFiles.length);
//	  
//	  for (File file : listOfFiles) {
//		  if (file.isFile()) {
//			  
//		       JSONParser jsonParser = new JSONParser();
//		       
//               //Parsing the contents of the JSON file
//               JSONObject jsonObject = (JSONObject) jsonParser.parse(new FileReader(file));
//               //Retrieving the array
//               JSONArray jsonArray = (JSONArray) jsonObject.get("attributes");
//               
//               System.out.println(jsonArray);
//			  
//			  
//		  }
//	  }
	  
	  try {
		InputStream is = new FileInputStream("C:\\Users\\LENOVO\\Downloads\\json_axo");
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	  
	  
	  
	  return ResponseEntity.ok("success");
	   
	   
   }
}
