package tr.org.lider.controllers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import tr.org.lider.constant.RoleConstants;
import tr.org.lider.entities.CommandImpl;
import tr.org.lider.entities.OperationType;
import tr.org.lider.entities.UserSessionImpl;
import tr.org.lider.ldap.DNType;
import tr.org.lider.ldap.LDAPServiceImpl;
import tr.org.lider.ldap.LdapEntry;
import tr.org.lider.ldap.LdapSearchFilterAttribute;
import tr.org.lider.ldap.SearchFilterEnum;
import tr.org.lider.models.ConfigParams;
import tr.org.lider.models.UserSessionsModel;
import tr.org.lider.security.CustomPasswordEncoder;
import tr.org.lider.services.CommandService;
import tr.org.lider.services.ConfigurationService;
import tr.org.lider.services.OperationLogService;
import tr.org.lider.services.UserService;


@Secured({RoleConstants.ROLE_ADMIN, RoleConstants.ROLE_USERS })
@RestController
@RequestMapping("/api/lider/user")
@Tag(name = "User", description = "User Rest Service")
public class UserController {
	
	Logger logger = LoggerFactory.getLogger(UserController.class);
	
	@Autowired
	private LDAPServiceImpl ldapService;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private ConfigurationService configurationService;
	
	@Autowired
	private CommandService commandService;
	
	@Autowired
	private CustomPasswordEncoder customPasswordEncoder;
	
	@Autowired
	private OperationLogService operationLogService;

	@Operation(summary = "Gets the ou detail of the selected entry.", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Returns the ou detail of the selected entry. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not get ou detail of the selected entry. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/ou-details")
	public ResponseEntity<List<LdapEntry>> task(LdapEntry selectedEntry) {
		List<LdapEntry> subEntries = null;
		try {
			subEntries = ldapService.findSubEntries(selectedEntry.getUid(), "(objectclass=*)",
					new String[] { "*" }, SearchScope.ONELEVEL);
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		Collections.sort(subEntries);
		selectedEntry.setChildEntries(subEntries);
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(subEntries);
	}
	
	@Operation(summary = "Gets organizational unit  of selected entry", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Returns ou of selected entry. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not get ou of selected entry. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@GetMapping(value = "/ou")
	public ResponseEntity<List<LdapEntry>> getOu(LdapEntry selectedEntry) {
		List<LdapEntry> subEntries = null;
		try {
			subEntries = ldapService.findSubEntries(selectedEntry.getUid(), "(&(objectclass=organizationalUnit)(objectclass=pardusLider))",
					new String[] { "*" }, SearchScope.ONELEVEL);
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		selectedEntry.setChildEntries(subEntries);
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(subEntries);
				
	}
	
	@Operation(summary = "Gets users list", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Returns users list. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not get users list. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/users")
	public ResponseEntity<List<LdapEntry>> getUsers() {
		List<LdapEntry> retList = new ArrayList<LdapEntry>();
		retList.add(ldapService.getLdapUserTree());
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(retList);
				
	}
	
	@Operation(summary = "Create ou", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Created ou. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not create ou.Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))),
			  @ApiResponse(responseCode = "226", description = "This uid was found.I am used", 
			    content = @Content(schema = @Schema(implementation = String.class)))})
	@PostMapping(value = "/add-ou",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> addOu(LdapEntry selectedEntry) {
		try {
			Map<String, String[]> attributes = new HashMap<String,String[]>();
			attributes.put("objectClass", new String[] {"organizationalUnit", "top", "pardusLider"} );
			attributes.put("ou", new String[] { selectedEntry.getOu() });
			
//			List<LdapSearchFilterAttribute> filterAttributesList = new ArrayList<LdapSearchFilterAttribute>();
//			List<LdapEntry> ouList = null;
//			filterAttributesList.add(new LdapSearchFilterAttribute("ou", selectedEntry.getOu(), SearchFilterEnum.EQ));	
//			ouList = ldapService.search(selectedEntry.getDistinguishedName(), filterAttributesList, new String[] {"*"});
			
			HttpHeaders headers = new HttpHeaders();
//			if(!ouList.isEmpty()){
//				headers.add("message", "This uid was found. Could not create ou");
//				return ResponseEntity.status(HttpStatus.IM_USED).headers(headers).build();
//			}

			String dn="ou="+selectedEntry.getOu()+","+selectedEntry.getParentName();
			
			ldapService.addEntry(dn, attributes);
			logger.info("OU created successfully RDN ="+dn);
			
			//get full of ou details after creation
			selectedEntry = ldapService.getEntryDetail(dn);
			
			String log = selectedEntry.getOu() + " has been created in " + selectedEntry.getDistinguishedName();
			try {
//				operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
				operationLogService.saveOperationLog(OperationType.CREATE, log, null);
			} catch (Exception e) {
				e.printStackTrace();
	    		return ResponseEntity
	    				.status(HttpStatus.EXPECTATION_FAILED)
	    				.headers(headers)
	    				.build();
			}
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(selectedEntry);
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
	}
	
	
	@Operation(summary = "Add user to selected entry", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Added user to selected entry. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not add user. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) ,
			  @ApiResponse(responseCode = "226", description = "This uid was found. I am used", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/add-user",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry>  addUser(LdapEntry selectedEntry) {
		try {
			String gidNumber="6000";
			int randomInt = (int)(1000000.0 * Math.random());
			String uidNumber= Integer.toString(randomInt);
			String home="/home/"+selectedEntry.getUid();

			Map<String, String[]> attributes = new HashMap<String, String[]>();
			attributes.put("objectClass", new String[] { "top", "posixAccount",
					"person","pardusLider","pardusAccount","organizationalPerson","inetOrgPerson"});
			attributes.put("cn", new String[] { selectedEntry.getCn() });
			attributes.put("mail", new String[] { selectedEntry.getMail() });
			attributes.put("gidNumber", new String[] { gidNumber });
			attributes.put("homeDirectory", new String[] { home });
			attributes.put("sn", new String[] { selectedEntry.getSn() });
			attributes.put("uid", new String[] { selectedEntry.getUid() });
			attributes.put("uidNumber", new String[] { uidNumber });
			attributes.put("loginShell", new String[] { "/bin/bash" });
			attributes.put("userPassword", new String[] { "{ARGON2}" + customPasswordEncoder.encode(selectedEntry.getUserPassword()) });
			attributes.put("homePostalAddress", new String[] { selectedEntry.getHomePostalAddress() });
			if(selectedEntry.getTelephoneNumber()!=null && selectedEntry.getTelephoneNumber()!="")
				attributes.put("telephoneNumber", new String[] { selectedEntry.getTelephoneNumber() });

			if(selectedEntry.getParentName()==null || selectedEntry.getParentName().equals("")) {
				selectedEntry.setParentName(configurationService.getUserLdapBaseDn());
			}
			
			List<LdapSearchFilterAttribute> filterAttributesList = new ArrayList<LdapSearchFilterAttribute>();
			List<LdapEntry> users = null;
			filterAttributesList.add(new LdapSearchFilterAttribute("uid", selectedEntry.getUid(), SearchFilterEnum.EQ));
			users = ldapService.search(configurationService.getUserLdapBaseDn(), filterAttributesList, new String[] {"*"});
			HttpHeaders headers = new HttpHeaders();
			
			if(!users.isEmpty()) {
				headers.add("message", "This uid was found. Could not create user ");
				return ResponseEntity.status(HttpStatus.IM_USED).headers(headers).build();
			}
			
			String rdn="uid="+selectedEntry.getUid()+","+selectedEntry.getParentName();
			ldapService.addEntry(rdn, attributes);
			selectedEntry.setAttributesMultiValues(attributes);
			selectedEntry.setDistinguishedName(selectedEntry.getUid());
			logger.info("User created successfully RDN ="+rdn);
			selectedEntry = ldapService.findSubEntries(rdn, "(objectclass=*)", new String[] {"*"}, SearchScope.OBJECT).get(0);
			
			String log = selectedEntry.getUid() + " has been created in " + selectedEntry.getDistinguishedName();
			try {
//				operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
				operationLogService.saveOperationLog(OperationType.CREATE, log, null);
			} catch (Exception e) {
				e.printStackTrace();
				return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).headers(headers).build();
			}
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(selectedEntry);
			
			
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
			return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).headers(headers).build();
		}
	}
	
	/**
	 * delete selected user
	 * @param selectedEntryArr
	 * @return
	 */
	@Operation(summary = "Delete select user", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Deleted select user.Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not delete user. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/delete-user")
	//@RequestMapping(method=RequestMethod.POST, value = "/deleteUser")
	public ResponseEntity<Boolean> deleteUser(@RequestBody LdapEntry[] selectedEntryArr) {
		try {
			LdapEntry userLdapEntry = null;
			for (LdapEntry ldapEntry : selectedEntryArr) {
				userLdapEntry = ldapEntry;
				if(ldapEntry.getType().equals(DNType.USER)) {
					List<LdapEntry> subEntries = ldapService.search("member", ldapEntry.getDistinguishedName(), new String[] {"*"});
					for (LdapEntry groupEntry : subEntries) {
						if(groupEntry.getAttributesMultiValues().get("member").length > 1) {
							ldapService.updateEntryRemoveAttributeWithValue(groupEntry.getDistinguishedName(), "member", ldapEntry.getDistinguishedName());
						} else {
							ldapService.deleteNodes(ldapService.getOuAndOuSubTreeDetail(groupEntry.getDistinguishedName()));
							//if there is any policy assigned to that group mark command as deleted
							List<CommandImpl> commands = commandService.findAllByDN(groupEntry.getDistinguishedName());
							for (CommandImpl command : commands) {
								command.setDeleted(true);
								commandService.updateCommand(command);
							}
						}
					}
					ldapService.deleteEntry(ldapEntry.getDistinguishedName());
					logger.info("User deleted successfully RDN ="+ldapEntry.getDistinguishedName());
				}
			}
			
			String log =  userLdapEntry.getDistinguishedName() + " has been deleted";
			try {
	//				operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
				operationLogService.saveOperationLog(OperationType.DELETE, log, null);
			} catch (Exception e) {
				e.printStackTrace();
				HttpHeaders headers = new HttpHeaders();
	    		return ResponseEntity
	    				.status(HttpStatus.EXPECTATION_FAILED)
	    				.headers(headers)
	    				.build();
			}
				
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(true);
					
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
	}
	
	/**
	 * edit only required user attributes
	 * return edited entry for update
	 * @param selectedEntry
	 * @return
	 */
	@Operation(summary = "Update user", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "User updated. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not update user.Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/edit-user",produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.POST, value = "/editUser",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> editUser(LdapEntry selectedEntry) {
		LdapEntry oldSelectedEntry = selectedEntry;
		try {
			if(!"".equals(selectedEntry.getCn())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "cn", selectedEntry.getCn());
			}
			if(!"".equals(selectedEntry.getSn())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "sn", selectedEntry.getSn());
			}
			if(!"".equals(selectedEntry.getTelephoneNumber())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "telephoneNumber", selectedEntry.getTelephoneNumber());
			}
			if(!"".equals(selectedEntry.getMail())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "mail", selectedEntry.getMail());
			}
			if(!"".equals(selectedEntry.getHomePostalAddress())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "homePostalAddress", selectedEntry.getHomePostalAddress());
			}
						
			selectedEntry = ldapService.findSubEntries(selectedEntry.getDistinguishedName(), "(objectclass=*)", new String[] {"*"}, SearchScope.OBJECT).get(0);

			String log = selectedEntry.getUid() + " has been updated ";	
			
			Map<String, Object> requestData = new HashMap<String, Object>();
			requestData.put("cn",oldSelectedEntry.getCn());
			requestData.put("sn",oldSelectedEntry.getSn());
			requestData.put("telephoneNumber",oldSelectedEntry.getTelephoneNumber());
			requestData.put("mail",oldSelectedEntry.getMail());
			requestData.put("homePostalAddress",oldSelectedEntry.getHomePostalAddress());

			ObjectMapper mapper = new ObjectMapper();
			String jsonString = "";
			try {
				jsonString = mapper.writeValueAsString(requestData);
			} catch (JsonProcessingException e1) {
				logger.error("Error occured while mapping request data to json. Error: " +  e1.getMessage());
			}
	
			try {	
				operationLogService.saveOperationLog(OperationType.UPDATE, log, jsonString.getBytes(),null, null, null);
//				operationLogService.saveOperationLog(OperationType.UPDATE, log, null);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(selectedEntry);
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
	}
	
	/**
	 * update user password
	 * @param selectedEntry
	 * @return
	 */
	
	@Operation(summary = "Update user password", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "User password updated. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not update user password.Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/update-user-password",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> updateUserPassword(LdapEntry selectedEntry) {
		try {
			tr.org.lider.security.User caller = tr.org.lider.services.AuthenticationService.getUser();
			String targetDn = selectedEntry.getDistinguishedName();
			boolean callerIsAdmin = caller != null && caller.getRoles() != null && caller.getRoles().contains(RoleConstants.ROLE_ADMIN);
			boolean callerOwnsTarget = caller != null && caller.getDn() != null && targetDn != null && caller.getDn().equalsIgnoreCase(targetDn.trim());
			if (!callerIsAdmin && !callerOwnsTarget) {
				List<LdapEntry> targetEntries = ldapService.findSubEntries(targetDn, "(objectclass=*)", new String[] {"liderPrivilege"}, SearchScope.OBJECT);
				boolean targetIsPrivileged = true;
				if (targetEntries != null && !targetEntries.isEmpty()) {
					String[] targetPrivileges = targetEntries.get(0).getAttributesMultiValues().get("liderPrivilege");
					targetIsPrivileged = targetPrivileges != null && java.util.Arrays.asList(targetPrivileges).contains(RoleConstants.ROLE_ADMIN);
				}
				if (targetIsPrivileged) {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
				}
			}
		
			if(!"".equals(selectedEntry.getUserPassword())){
				ldapService.updateEntry(selectedEntry.getDistinguishedName(), "userPassword", "{ARGON2}" + customPasswordEncoder.encode(selectedEntry.getUserPassword()));
			}
			selectedEntry = ldapService.findSubEntries(selectedEntry.getDistinguishedName(), "(objectclass=*)", new String[] {"*"}, SearchScope.OBJECT).get(0);
			
			String log = selectedEntry.getUid() + " password has been changed";
			try {
//				operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
				operationLogService.saveOperationLog(OperationType.CHANGE_PASSWORD, log, null);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(selectedEntry);
					
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
	}
	
	/**
	 * getting password policy  
	 * @param selectedEntry
	 * @return
	 */
	
	@Operation(summary = "Gets password policy", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "Could not get password polices.Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@GetMapping(value = "/password-polices",produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.POST, value = "/getPasswordPolices",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<List<LdapEntry>> getPasswordPolices() {
		List<LdapEntry> passwordPolicies = null;
		try {
			passwordPolicies = ldapService.findSubEntries(configurationService.getLdapRootDn(), "(objectclass=pwdPolicy)",
					new String[] { "*" }, SearchScope.SUBTREE);

		} catch (LdapException e) {
			e.printStackTrace();
		}
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(passwordPolicies);
				
	}
	
	/**
	 * set password policy to user  
	 * @param passwordPolicy
	 * @return
	 */
	@Operation(summary = "Create password policy", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "Could not change password policies.Unexpected error occured.", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/password-policy",produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.POST, value = "/setPasswordPolicy",produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> setPasswordPolicy(@RequestParam(value = "dn", required=true) String dn,@RequestParam(value = "passwordPolicy", required=true) String passwordPolicy) {
		LdapEntry selectedEntry=null;
		try {
			ldapService.updateEntry(dn, "pwdPolicySubentry", passwordPolicy);
			
		selectedEntry = ldapService.findSubEntries(dn, "(objectclass=*)", new String[] {"*"}, SearchScope.OBJECT).get(0);


		String log = selectedEntry.getDistinguishedName() + " has been changed ";
		try {
//			operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
			operationLogService.saveOperationLog(OperationType.UPDATE, log, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(selectedEntry);
				
	}
	
	/**
	 * get users under sent ORGANIZATIONAL_UNIT 
	 * @param selectedEntryArr
	 * @return
	 */
	@Operation(summary = "", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/users-under-ou")
	//@RequestMapping(value = "/getUsersUnderOU", method = { RequestMethod.POST })
	public ResponseEntity<List<LdapEntry>> getUsersUnderOU(HttpServletRequest request,Model model, @RequestBody LdapEntry[] selectedEntryArr) {
		List<LdapEntry> userList=new ArrayList<>();
		for (LdapEntry ldapEntry : selectedEntryArr) {
			List<LdapSearchFilterAttribute> filterAttributes = new ArrayList<LdapSearchFilterAttribute>();
			LdapSearchFilterAttribute fAttr = new LdapSearchFilterAttribute("objectClass", "pardusAccount",	SearchFilterEnum.EQ);
			filterAttributes.add(fAttr);
			try {
				List<LdapEntry> retList=ldapService.findSubEntries(ldapEntry.getDistinguishedName(), "(objectclass=pardusAccount)", new String[] { "*" }, SearchScope.SUBTREE);
				for (LdapEntry ldapEntry2 : retList) {
					boolean isExist=false;
					for (LdapEntry ldapEntryAhenk : userList) {
						if(ldapEntry2.getEntryUUID().equals(ldapEntryAhenk.getEntryUUID())) {
							isExist=true;
							break;
						}
					}
					if(!isExist) {
						userList.add(ldapEntry2);
					}
				}
			} catch (LdapException e) {
				e.printStackTrace();
				HttpHeaders headers = new HttpHeaders();
	    		return ResponseEntity
	    				.status(HttpStatus.EXPECTATION_FAILED)
	    				.headers(headers)
	    				.build();
			}
		}
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(userList);
	}

	//add new group and add selected agents
	@Operation(summary = "Create new group", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Created new group under ou.Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not create group under ou. Unexpected error occured", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/create-new-group", produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.POST ,value = "/createNewGroup", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> createNewUserGroup(@RequestParam(value = "selectedOUDN", required=false) String selectedOUDN,
			@RequestParam(value = "groupName", required=true) String groupName,
			@RequestParam(value = "checkedList[]", required=true) String[] checkedList) {
		String newGroupDN = "";
		//to return newly added entry with its details
		LdapEntry entry;
		if(selectedOUDN == null || selectedOUDN.equals("")) {
			newGroupDN = "cn=" +  groupName +","+ configurationService.getAhenkGroupLdapBaseDn();
		} else {
			newGroupDN = "cn=" +  groupName +","+ selectedOUDN;
		}
		Map<String, String[]> attributes = new HashMap<String,String[]>();
		attributes.put("objectClass", new String[] {"groupOfNames", "top", "pardusLider"} );
		attributes.put("liderGroupType", new String[] {"USER"} );
		try {
			//when single dn comes spring boot takes it as multiple arrays
			//so dn must be joined with comma
			//if member dn that will be added to group is cn=user1,ou=Groups,dn=liderahenk,dc=org
			//spring boot gets this param as array which has size 4
			Boolean checkedArraySizeIsOne = true;
			for (int i = 0; i < checkedList.length; i++) {
				if(checkedList[i].contains(",")) {
					checkedArraySizeIsOne = false;
					break;
				}
			}
			if(checkedArraySizeIsOne ) {
				attributes.put("member", new String[] {String.join(",", checkedList)} );
			} else {
				attributes.put("member", checkedList );
			}
			ldapService.addEntry(newGroupDN , attributes);
			entry = ldapService.getEntryDetail(newGroupDN);
			
			String log = newGroupDN + " has been created in";
			operationLogService.saveOperationLog(OperationType.CREATE, log, null, null, null, null);
			
		} catch (LdapException e) {
			System.out.println("Error occured while adding new group.");
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(entry);
	}
	
	/**
	 * delete user ou's
	 * @param selectedEntryArr
	 * @return
	 */
	
	@Operation(summary = "Delete user under organizational unit", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Deleted user under organizational unit.Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not delete user under ou. Unexpected error occured", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/delete-user-ou")
	//@RequestMapping(method=RequestMethod.POST, value = "/deleteUserOu")
	public ResponseEntity<Boolean> deleteUserOu(@RequestBody LdapEntry[] selectedEntryArr) {
		LdapEntry deletedLdapEntry = null;
		try {
			for (LdapEntry ldapEntry : selectedEntryArr) {
				deletedLdapEntry = ldapEntry;
				if(ldapEntry.getType().equals(DNType.ORGANIZATIONAL_UNIT)) {
					ldapService.updateOLCAccessRulesAfterEntryDelete(ldapEntry.getDistinguishedName());
					ldapService.deleteNodes(ldapService.getOuAndOuSubTreeDetail(ldapEntry.getDistinguishedName()));
				}
			}

			String log = deletedLdapEntry.getDistinguishedName() + " has been deleted";
			operationLogService.saveOperationLog(OperationType.DELETE, log, null, null, null, null);
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(true);
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity
					.status(HttpStatus.EXPECTATION_FAILED)
					.body(false);
		}
	}
	
	/**
	 * get last user
	 * @param selectedEntryArr
	 * @return
	 */
	
	@Operation(summary = "", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@GetMapping(value = "/last-user")
	//@RequestMapping(method=RequestMethod.POST, value = "/getLastUser")
	public ResponseEntity<LdapEntry> getLastUser() {
		String globalUserOu = configurationService.getUserLdapBaseDn();
		LdapEntry lastUser=null;
		try {
			
			String filter="(&(objectClass=inetOrgPerson)(createTimestamp>=20200301000000Z))";
			
			List<LdapEntry> usersEntrylist = ldapService.findSubEntries(globalUserOu, filter,new String[] { "*" }, SearchScope.SUBTREE);
			if(usersEntrylist.size()>0)
			lastUser= usersEntrylist.get(usersEntrylist.size()-1);
			
			logger.info("last user : "+lastUser);
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(lastUser);
	}
	
	@Operation(summary = "Gets user session", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "Could not get user session. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@GetMapping(value = "/user-session/page-number/{pageNumber}/page-size/{pageSize}/uid/{uid}")
	//@RequestMapping(method=RequestMethod.POST, value = "/getUserSessions")
	public ResponseEntity<?> getUserSessions(
			@PathVariable String uid,
			@PathVariable int pageNumber,
			@PathVariable int pageSize) {
		List<UserSessionsModel> userSessions = null;
		Page<UserSessionImpl> userSessionsDb = null;
		PageImpl<?> userSessionsDb2 = null;
		
		try {
			userSessionsDb = userService.getUserSessions(pageNumber, pageSize, uid);
			userSessions = new ArrayList<>();
			for (UserSessionImpl userSessionImpl : userSessionsDb.getContent()) {				
				UserSessionsModel model = new UserSessionsModel();
				model.setAgent(userSessionImpl.getAgent());
				model.setCreateDate(userSessionImpl.getCreateDate());
				model.setId(userSessionImpl.getId());
				model.setSessionEvent(userSessionImpl.getSessionEvent());
				model.setUserIp(userSessionImpl.getUserIp());
				model.setUsername(userSessionImpl.getUsername());
				userSessions.add(model);
			}
			userSessionsDb2 = new PageImpl<>(userSessions, userSessionsDb.getPageable(), userSessionsDb.getTotalElements());
			
		} catch (Exception e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}

		return ResponseEntity
				.status(HttpStatus.OK)
				.body(userSessionsDb2);
				
	}
	
	@Operation(summary = "Move entry", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "Could not move entry. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/move/entry", produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.POST ,value = "/move/entry", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> moveEntry(@RequestParam(value="sourceDN", required=true) String sourceDN,
			@RequestParam(value="destinationDN", required=true) String destinationDN,
			@RequestParam(value="uid", required=true) String uid) {
		try {
			String newUserDN = "uid=" + uid + "," + destinationDN;
			ldapService.moveEntry(sourceDN, destinationDN);
			String log = sourceDN + " has been moved to " + destinationDN;
			operationLogService.saveOperationLog(OperationType.MOVE, log, null, null, null, null);
			LdapEntry ldapEntry = ldapService.getEntryDetail(newUserDN);
			
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(ldapEntry);
			
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity
					.status(HttpStatus.EXPECTATION_FAILED)
					.body(null);
		}
	}
	
	/**
	 * 
	 * @param searchDn
	 * @param key
	 * @param value
	 * @return
	 */
	@Operation(summary = "Delete attribute and values", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Deleted attribute and vulues. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not delete attribute. Unexpected error occurred", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@DeleteMapping(value = "/attribute-with-value/dn/{dn}/attribute/{attribute}/value/{value}", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<LdapEntry> removeAttributeWithValue(
			@PathVariable String dn,
			@PathVariable String attribute, 
			@PathVariable String value) {
		
		LdapEntry entry=null;
		try {
			ldapService.updateEntryRemoveAttributeWithValue(dn, attribute, value);
			entry = ldapService.findSubEntries(dn, "(objectclass=*)", new String[] {"*"}, SearchScope.OBJECT).get(0);
			
			String log = entry.getUid() + " " + attribute + " has been deleted" ;
			
			Map<String, Object> requestData = new HashMap<String, Object>();
			requestData.put(attribute, value);
			ObjectMapper mapper = new ObjectMapper();
			String jsonString = "";
			try {
				jsonString = mapper.writeValueAsString(requestData);
				operationLogService.saveOperationLog(OperationType.DELETE, log, jsonString.getBytes(), null, null, null);
			} catch (JsonProcessingException e1) {
				logger.error("Error occured while mapping request data to json. Error: " +  e1.getMessage());
			}			
		} catch (LdapException e) {
			e.printStackTrace();
			HttpHeaders headers = new HttpHeaders();
    		return ResponseEntity
    				.status(HttpStatus.EXPECTATION_FAILED)
    				.headers(headers)
    				.build();
		}
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(entry);
				
	}
	
	@Operation(summary = "Gets configurations", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = "Configurations updated. Successful"),
			  @ApiResponse(responseCode = "417", description = "Could not update configurations. Unexpected error occured ", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@GetMapping(value = "/configurations", produces = MediaType.APPLICATION_JSON_VALUE)
	//@RequestMapping(method=RequestMethod.GET, value = "/configurations", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<HashMap<String, Object>> getConfigParams() {
		ConfigParams configParams = configurationService.getConfigParams();
		HashMap<String, Object> configMap = new HashMap<String, Object>();
		configMap.put("userGroupLdapBaseDn", configParams.getUserGroupLdapBaseDn());
		configMap.put("userLdapBaseDn", configParams.getUserLdapBaseDn());
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(configMap);
				
	}
	
	@Operation(summary = "Make user Enable or Disable ", description = "", tags = { "user" })
	@ApiResponses(value = { 
			  @ApiResponse(responseCode = "200", description = ""),
			  @ApiResponse(responseCode = "417", description = "", 
			    content = @Content(schema = @Schema(implementation = String.class))) })
	@PostMapping(value = "/user-enable-disable")
	public ResponseEntity<?> updateDomainAdmin(@RequestParam(value = "dn") String dn,
			@RequestParam(value = "isDisableUser") Boolean isDisableUser) {
		try {
			if (isDisableUser) {
				ldapService.updateEntryAddAtribute(dn, "pwdAccountLockedTime", "20280112065328.185Z");
			} else {
				try {
					ldapService.updateEntryRemoveAttributeWithValue(dn, "pwdAccountLockedTime", "20280112065328.185Z");
				} catch (LdapException e) {
					e.printStackTrace();
					HttpHeaders headers = new HttpHeaders();
		    		return ResponseEntity
		    				.status(HttpStatus.EXPECTATION_FAILED)
		    				.headers(headers)
		    				.build();
				}
			}
			Map<String, Object> requestData = new HashMap<String, Object>();
			requestData.put("dn", dn);
			ObjectMapper dataMapper = new ObjectMapper();
			String jsonString = dataMapper.writeValueAsString(requestData);
			
			if (isDisableUser) {
				String logAdded = "The user has been disabled. " + dn;
				operationLogService.saveOperationLog(OperationType.UPDATE, logAdded, jsonString.getBytes(), null, null, null);
			} else {
				String logDeleted = "The user has been enabled. " + dn;
				operationLogService.saveOperationLog(OperationType.UPDATE, logDeleted, jsonString.getBytes(), null, null, null);
			}
			
			LdapEntry selectedEntry = ldapService.getEntryDetail(dn);
			return ResponseEntity
					.status(HttpStatus.OK)
					.body(selectedEntry);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<String[]>(new String[] {"Hata oluştu"}, HttpStatus.EXPECTATION_FAILED);
		}
	}
}
