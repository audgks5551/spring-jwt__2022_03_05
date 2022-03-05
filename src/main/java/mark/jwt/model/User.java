package mark.jwt.model;


import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static javax.persistence.GenerationType.IDENTITY;

@Data
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String roles;

    public List<String> getRoleList() {
        if (this.roles.length() > 0) {
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }
}
