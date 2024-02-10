package web.testsecurity.UserService;

import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import web.testsecurity.UserEntity;
import web.testsecurity.entities.RefreshToken;
import web.testsecurity.exception.JWTexception;
import web.testsecurity.repository.UserRepository;
import web.testsecurity.security.AppUserDetails;
import web.testsecurity.security.jwt.JwtUtils;
import web.testsecurity.web.*;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityService {
    private final JwtUtils jwtUtils;
    private final RefreshTokenService tokenService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;






    public AuthResponse authUser(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(), request.getPassword()
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        RefreshToken refreshToken = tokenService.createRefreshToken(userDetails.getId());
        return AuthResponse.builder()
                .id(userDetails.getId())
                .token(jwtUtils.generateJwtToken(userDetails))
                .refreshToken(refreshToken.getToken())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .build();
    }

    public void register(UserRequests requests) {
        var user = UserEntity.builder()
                .username(requests.getUsername())
                .email(requests.getEmail())
                .password(passwordEncoder.encode(requests.getPassword()))
                .build();
        user.setRoleTypes(requests.getRoleTypes());
        userRepository.save(user);
    }
    public RefreshTokenResponse refreshTokenResponse(RefreshTokenRequest request){
        String requestRefreshToken = request.getRefreshToken();
        return tokenService.findByRefreshToken(requestRefreshToken)
                .map(tokenService::checkRefreshToken)
                .map(RefreshToken::getId)
                .map(userId->{
                    UserEntity tokenOwner = userRepository.findById(userId)
                            .orElseThrow(()->new JWTexception("Exception trying to get token for userId: "+userId));
                    String token = jwtUtils.generateTokenFromUsername(tokenOwner.getUsername());
                    return new RefreshTokenResponse(token,tokenService.createRefreshToken(userId).getToken());
                }).orElseThrow(()->new JWTexception("Refresh token not found"+requestRefreshToken));


    }
    public void logout(){
        var currentPrincipal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (currentPrincipal instanceof AppUserDetails userDetails){
            Long userId = userDetails.getId();
            tokenService.deleteByUserId(userId);
        }

    }
























}
