package org.project1.shopweb.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.project1.shopweb.component.JwtTokenUtil;
import org.project1.shopweb.component.LocalizationUtils;
import org.project1.shopweb.dto.UpdateUserDTO;
import org.project1.shopweb.exception.DemoI18nException;
import org.project1.shopweb.exception.ErrorCode;
import org.project1.shopweb.model.Role;
import org.project1.shopweb.model.Token;
import org.project1.shopweb.model.User;
import org.project1.shopweb.dto.UserDTO;
import org.project1.shopweb.repository.RoleRepository;
import org.project1.shopweb.repository.TokenRepository;
import org.project1.shopweb.repository.UserRepository;
import org.project1.shopweb.exception.NotFoundException;
import org.project1.shopweb.utils.MessageKeys;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements IUserService{
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final LocalizationUtils localizationUtils;
    private final TokenRepository  tokenRepository;

    @Override
    public User createUser(UserDTO userDTO) throws Exception {

        //register user
        String phoneNumber = userDTO.getPhoneNumber();
        // Kiểm tra xem số điện thoại đã tồn tại hay chưa
        if(userRepository.existsByPhoneNumber(phoneNumber)) {
            throw new DemoI18nException(ErrorCode.REGISTER_FAILED,"Phone number already exists");
        }
        Role role =roleRepository.findById(userDTO.getRoleId())
                .orElseThrow(() ->
                        new DemoI18nException(ErrorCode.REGISTER_FAILED,localizationUtils.getLocalizationMessages(MessageKeys.ROLE_NOT_FOUND)));
        if(role.getName().toUpperCase().equals(Role.ADMIN)) {
            throw new DemoI18nException(ErrorCode.REGISTER_FAILED,"You cannot register an admin account");
        }
        //convert from userDTO => user
        User newUser = User.builder()
                .fullName(userDTO.getFullName())
                .phoneNumber(userDTO.getPhoneNumber())
                .password(userDTO.getPassword())
                .address(userDTO.getAddress())
                .dateOfBirth(userDTO.getDateOfBirth())
                .facebookAccountId(userDTO.getFacebookAccountId())
                .googleAccountId(userDTO.getGoogleAccountId())
                .active(true)
                .build();

        newUser.setRole(role);
        // Kiểm tra nếu có accountId, không yêu cầu password
        if (userDTO.getFacebookAccountId() == 0 && userDTO.getGoogleAccountId() == 0) {
            String password = userDTO.getPassword();
            String encodedPassword = passwordEncoder.encode(password);
            newUser.setPassword(encodedPassword);
        }
        return userRepository.save(newUser);
    }


    @Override
    public String login(String phonenumber, String password,Long roleId) throws  Exception{
        Optional<User> optionalUser = userRepository.findByPhoneNumber(phonenumber);
        if(optionalUser.isEmpty()){
            throw new DemoI18nException(ErrorCode.LOGIN_FAILED,localizationUtils.getLocalizationMessages(MessageKeys.WRONG_USER_PASS));
        }
        User existUser = optionalUser.get();
        if(existUser.getFacebookAccountId() == 0 && existUser.getGoogleAccountId() == 0){
            if(!passwordEncoder.matches(password,existUser.getPassword())){
                throw new DemoI18nException(ErrorCode.LOGIN_FAILED,localizationUtils.getLocalizationMessages(MessageKeys.WRONG_USER_PASS));
            }
        }

        Optional<Role> optionalRole = roleRepository.findById(roleId);
        if(optionalRole.isEmpty() || !roleId.equals(existUser.getRole().getId())) {
            throw new DemoI18nException(ErrorCode.LOGIN_FAILED,localizationUtils.getLocalizationMessages(MessageKeys.ROLE_NOT_FOUND));
        }
        if(!optionalUser.get().getActive()) {
            throw new DemoI18nException(ErrorCode.LOGIN_FAILED,localizationUtils.getLocalizationMessages(MessageKeys.USER_IS_lOCKED));
        }



        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                phonenumber,password,existUser.getAuthorities()
        );
        authenticationManager.authenticate(token);
        return jwtTokenUtil.generateToken(existUser);
    }

    @Override
    public User getUserDetailFromToken(String token) {

        if(jwtTokenUtil.isTokenExpired(token)){
            throw new RuntimeException("this token is expired");

        }
        String phoneNumber = jwtTokenUtil.extractPhoneNumber(token);
        Optional<User> user = userRepository.findByPhoneNumber(phoneNumber);

     if(user.isPresent()){
         log.info("tra ve user");
         return user.get();
     } else {
        log.info("not found");
         throw new RuntimeException("User Not found");
     }



    }

    @Override
    public User updateUser(Long userId, UpdateUserDTO userDTO) {
        User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("user Not Found"));

        String newPhoneNumber = userDTO.getPhoneNumber();
        if(userRepository.existsByPhoneNumber(userDTO.getPhoneNumber())
         && !newPhoneNumber.equals(existingUser.getPhoneNumber())){

            throw new NotFoundException("this phone number is already exist");
        }


        if (userDTO.getFullName() != null) {
            existingUser.setFullName(userDTO.getFullName());
        }
        if (newPhoneNumber != null) {
            existingUser.setPhoneNumber(newPhoneNumber);
        }
        if (userDTO.getAddress() != null) {
            existingUser.setAddress(userDTO.getAddress());
        }
        if (userDTO.getDateOfBirth() != null) {
            existingUser.setDateOfBirth(userDTO.getDateOfBirth());
        }
        if (userDTO.getFacebookAccountId() > 0) {
            existingUser.setFacebookAccountId(userDTO.getFacebookAccountId());
        }
        if (userDTO.getGoogleAccountId() > 0) {
            existingUser.setGoogleAccountId(userDTO.getGoogleAccountId());
        }
        if(userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()){
            if(!userDTO.getPassword().equals(userDTO.getRetypePassword())){
                throw new NotFoundException("Password does not match");
            }
            String newPassword = userDTO.getPassword();
            String encodePassword = passwordEncoder.encode(newPassword);
            existingUser.setPassword(encodePassword);

        } else {
            throw new  NotFoundException("bad password"); // actually valid from fe so do have to worry
        }
        return userRepository.save(existingUser);


    }

    @Override
    public User getUserDetailsFromRefreshToken(String refreshToken) throws Exception {
        Token existingToken = tokenRepository.findByRefreshToken(refreshToken);
        if(jwtTokenUtil.isTokenExpired(existingToken.getToken())){
            log.info(existingToken.getToken());

            throw new NotFoundException("token not valid");
        }
        return existingToken.getUser();

    }

    @Override
    public Page<User> findAll(String keyword, Pageable pageable) throws Exception {
        return userRepository.findAll(keyword,pageable);
    }

    @Override
    @Transactional
    public void resetPwd(String newPass, Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("not found user"));
        String encodedPassword = passwordEncoder.encode(newPass);
        user.setPassword(encodedPassword);
        userRepository.save(user);
        List<Token> tokenList = tokenRepository.findByUser(user);
        for(Token t : tokenList){
            tokenRepository.delete(t);
        }
    }

    @Override
    public void blockOrEnable(Long id, Boolean active) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("not found user"));
        user.setActive(active);
        userRepository.save(user);
    }


}
