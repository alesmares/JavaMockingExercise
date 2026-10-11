import cz.upce.fei.inptp.databasedependency.business.AuthenticationService;
import cz.upce.fei.inptp.databasedependency.dao.PersonDAO;
import cz.upce.fei.inptp.databasedependency.entity.Person;
import cz.upce.fei.inptp.databasedependency.entity.PersonRole;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {
    
    @Mock
    private PersonDAO persondao;
    
    @Mock
    private PersonRole personrole;
    
    @InjectMocks
    private AuthenticationService authenticateServ;
    
    @Test
    public void AuthenticatePass() {
        String login = "user";
        String password = "pass";
 
        String hashedPassword = AuthenticationService.encryptPassword(password);
        Person newPerson = new Person(1, login, hashedPassword);

        when(persondao.load("name = '" + login + "'")).thenReturn(newPerson);
 
        assertTrue(authenticateServ.Authenticate(login,password));
    }

    @Test
    public void AuthenticateFail() {
        String login = "user";
        String pass = "pass";
        String invalidPass = "invalid";
        
        String hashedPass = AuthenticationService.encryptPassword(pass);
        Person newPerson = new Person(1, login, hashedPass);
        
        when(persondao.load("name = '" + login + "'")).thenReturn(newPerson);

        assertFalse(authenticateServ.Authenticate(login, invalidPass));
    }
    
    @Test
    public void AuthenticateUserNotExisting() {
        String login = "user";
        String pass = "pass";
        
        when(persondao.load("name = '" + login + "'")).thenReturn(null);
        
        assertFalse(authenticateServ.Authenticate(login, pass));
    }
}
