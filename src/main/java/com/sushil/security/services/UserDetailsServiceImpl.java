package com.sushil.security.services;

import com.sushil.models.Otp;
import com.sushil.models.User;
import com.sushil.repositories.OtpRepository;
import com.sushil.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {


    private static final int OTP_EXPIRATION_TIME_IN_MINUTES = 10;
    private static final int OTP_LENGTH = 6;
    @Autowired
    OtpRepository otpRepository;

    @Autowired
    UserRepository userRepository;
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(()->new UsernameNotFoundException("User not found with username: {}"+username));
        return UserDetailsImpl.build(user);
    }

    private Map<String,Integer> otpMap=new ConcurrentHashMap<>();

   /* public void sendOtp(String mobileNumber) {

        int otp=generateOtp();
        otpMap.put(mobileNumber,otp);
        sendSms(mobileNumber,"Your OTP is: "+otp);
        
    }
*/
    private void sendSms(String mobileNumber, String message) {
        System.out.println("Sending SMS to "+ mobileNumber+": "+message);
    }

    private int generateOtp() {
        return new Random().nextInt(9000)+1000;
    }

    public void generateOtp(String mobileNo) throws Throwable {

        User user = (User) userRepository.findByMobileNo(mobileNo)
                .orElseThrow(() -> new Exception("User not found with mobile: " + mobileNo));

        Otp otp = otpRepository.findByUserId(user.getId()).orElse(new Otp());
        if (!otp.getOtp().equals(otp)) {
            throw new Exception("Invalid OTP");
        }
        if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new Exception("OTP has expired");
        }
        otp.setUserId(user.getId());
        otp.setOtp(generateRandomOtp());
        otp.setExpiryTime(LocalDateTime.now().plusMinutes(OTP_EXPIRATION_TIME_IN_MINUTES));

        otpRepository.save(otp);

        //smsService.sendSms(mobile, "Your OTP is " + otp.getOtp() + ". It will expire in "+ OTP_EXPIRATION_TIME_IN_MINUTES + " minutes.");

    }
    private String generateRandomOtp() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < OTP_LENGTH; i++) {
            sb.append(random.nextInt(10));
        }

        return sb.toString();
    }
}
