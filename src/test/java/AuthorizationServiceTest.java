import cz.upce.fei.inptp.databasedependency.business.AccessOperationType;
import cz.upce.fei.inptp.databasedependency.business.AuthorizationService;
import cz.upce.fei.inptp.databasedependency.dao.PersonDAO;
import cz.upce.fei.inptp.databasedependency.dao.PersonRolesDAO;
import cz.upce.fei.inptp.databasedependency.entity.Person;
import cz.upce.fei.inptp.databasedependency.entity.PersonRole;
import cz.upce.fei.inptp.databasedependency.entity.Role;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.Mockito.when;
import java.lang.reflect.Method;

@ExtendWith(MockitoExtension.class)
public class AuthorizationServiceTest {
    
    @Mock
    private PersonDAO persondao;
    
    @Mock
    private PersonRolesDAO personrole;
    
    @InjectMocks
    private AuthorizationService authorizationServ;
    
    @Test
    public void SubsectionAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String section = "/section/subsection";
        
        Role role = new Role("/section/subsection","rw",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, section, AccessOperationType.Write));
    }
    
    @Test
    public void SubsectionAuthorizationFail() {
        Person person = new Person(1,"user","pass");
        String section = "/section/subsection";
        
        Role role = new Role("/section/subsection","ro",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertFalse(authorizationServ.Authorize(person, section, AccessOperationType.Write));
    }
    
    @Test
    public void SectionAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/section","rw",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void SectionAuthorizationFail() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/section","ro",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertFalse(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void RootAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/","rw",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void RootAuthorizationFail() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/","ro",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertFalse(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void SubsectionAdminAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/section/subsection","admin",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void SectionAdminAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/section","admin",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void RootAdminAuthorizationPass() {
        Person person = new Person(1,"user","pass");
        String requestedSection = "/section/subsection";
        
        Role role = new Role("/","admin",null);
        
        PersonRole pRole = new PersonRole(person, List.of(role));
        String dummyWhereString = "dummy_query";
        
        when(persondao.getRoleWhereStringFor(person)).thenReturn(dummyWhereString);
        when(personrole.load(dummyWhereString)).thenReturn(pRole);
        
        assertTrue(authorizationServ.Authorize(person, requestedSection, AccessOperationType.Write));
    }
    
    @Test
    public void getUpperFromSubsubsection() throws Exception {
        Method getUpperLevelMethod = AuthorizationService.class.getDeclaredMethod("getUpperLevel", String.class);
        getUpperLevelMethod.setAccessible(true);
        
        String result = (String) getUpperLevelMethod.invoke(authorizationServ, "/section/subsection/subsubsection");
        assertEquals("/section/subsection", result);
    }
    
    @Test
    public void getUpperFromSubsection() throws Exception {
        Method getUpperLevelMethod = AuthorizationService.class.getDeclaredMethod("getUpperLevel", String.class);
        getUpperLevelMethod.setAccessible(true);
        
        String result = (String) getUpperLevelMethod.invoke(authorizationServ, "/section/subsection");
        assertEquals("/section", result);
    }
    
    @Test
    public void getUpperFromSection() throws Exception {
        Method getUpperLevelMethod = AuthorizationService.class.getDeclaredMethod("getUpperLevel", String.class);
        getUpperLevelMethod.setAccessible(true);
        
        String result = (String) getUpperLevelMethod.invoke(authorizationServ, "/section");
        assertEquals("/", result);
    }
    
    @Test
    public void getUpperFromRoot() throws Exception {
        Method getUpperLevelMethod = AuthorizationService.class.getDeclaredMethod("getUpperLevel", String.class);
        getUpperLevelMethod.setAccessible(true);
        
        String result = (String) getUpperLevelMethod.invoke(authorizationServ, "/");
        assertEquals("", result);
    }
}
