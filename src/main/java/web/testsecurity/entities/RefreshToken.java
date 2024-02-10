package web.testsecurity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@RedisHash("refresh_tokens")
public class RefreshToken {
    @Id
    @Indexed
    private Long id;
    @Indexed
    private Long userId;
    @Indexed
    private String token;
    @Indexed
    private Instant expiryDate;
}
