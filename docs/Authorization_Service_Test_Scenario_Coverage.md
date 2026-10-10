# Authorization Service -- Test Scenario Coverage

**Repository:**
[alzandoo/alzando-authorization-service](https://github.com/alzandoo/alzando-authorization-service)\
**Branch reviewed:** `main`

## Status legend

-   ✅ **Implemented** --- corresponding test identified in reviewed
    repository files.
-   🟡 **Partially covered / verify assertions** --- related test
    exists, but full behavior/assertions need confirmation.
-   ⬜ **Not verified** --- no explicit matching test identified in
    reviewed files; inspect the full suite before calling it missing.
-   ❌ **Not implemented** --- use only after confirming absence from
    the complete current suite.

> **Baseline:** The previously shared inventory contained 84 test
> functions. Parametrized tests may result in more executed cases. The
> latest previously reported full-suite result was
> `87 passed, 1 skipped`; this is historical and has not been freshly
> rerun for this report.

## 1. Application Management

  ---------------------------------------------------------------------------------------
  ID             Test scenario             Expected result  Status         Priority
  -------------- ------------------------- ---------------- -------------- --------------
  APP-01         Register valid            Application      ✅ Implemented P1
                 application               created                         

  APP-02         Register duplicate        Duplicate        ⬜ Not         P1
                 application ID            rejected         verified       

  APP-03         Missing required          Validation error ⬜ Not         P1
                 application fields                         verified       

  APP-04         Malformed application     Request rejected ⬜ Not         P2
                 data                                       verified       

  APP-05         Use inactive application  Access denied    ✅ Implemented P1

  APP-06         Access disabled           Access denied    🟡 Partially   P1
                 application service                        covered /      
                                                            verify         
                                                            assertions     

  APP-07         Cross-application         Reference        ✅ Implemented P1
                 resource reference        rejected                        

  APP-08         Service                   Valid config     ✅ Implemented P1
                 catalogue/configuration   accepted;                       
                                           invalid config                  
                                           rejected                        

  APP-09         Public/confidential       Client type      ✅ Implemented P1
                 client behavior           policy enforced                 

  APP-10         Invalid client            Authentication   ✅ Implemented P1
                 credentials               rejected                        
  ---------------------------------------------------------------------------------------

## 2. User Registration and Account Management

  ---------------------------------------------------------------------------------
  ID             Test scenario     Expected result  Status           Priority
  -------------- ----------------- ---------------- ---------------- --------------
  USR-01         Register valid    Account created  🟡 Partially     P1
                 user              according to     covered / verify 
                                   signup policy    assertions       

  USR-02         Register          Duplicate        ✅ Implemented   P1
                 duplicate email   rejected                          

  USR-03         Missing required  Validation error ✅ Implemented   P1
                 phone/fields                                        

  USR-04         Signup requires   Account follows  ✅ Implemented   P1
                 email             verification                      
                 verification      policy                            

  USR-05         Invalid           Validation error ⬜ Not verified  P1
                 email/malformed                                     
                 payload                                             

  USR-06         Weak password     Password policy  ⬜ Not verified  P1
                                   enforced, if                      
                                   configured                        

  USR-07         Login with        Authentication   🟡 Partially     P1
                 inactive account  rejected         covered / verify 
                                                    assertions       

  USR-08         Deactivate        Sessions handled 🟡 Partially     P1
                 account with      according to     covered / verify 
                 active sessions   policy           assertions       

  USR-09         Access another    Access denied    🟡 Partially     P1
                 user's resources                   covered / verify 
                                                    resource-level   
                                                    assertions       
  ---------------------------------------------------------------------------------

## 3. Authentication, Verification and MFA

  -------------------------------------------------------------------------------------
  ID             Test scenario       Expected result      Status         Priority
  -------------- ------------------- -------------------- -------------- --------------
  AUTH-01        Login with valid    Authentication       ✅ Implemented P1
                 credentials         succeeds                            

  AUTH-02        Incorrect password  Authentication       ✅ Implemented P1
                                     rejected                            

  AUTH-03        Repeated failed     Lockout/protection   ✅ Implemented P1
                 password attempts   enforced                            

  AUTH-04        Unknown account     Rejected without     🟡 Partially   P1
                 login               account enumeration  covered /      
                                                          verify         
                                                          assertions     

  AUTH-05        Missing/malformed   Documented           ⬜ Not         P1
                 login fields        validation error     verified       

  AUTH-06        Valid email/phone   Verification         ✅ Implemented P1
                 OTP                 succeeds                            

  AUTH-07        Incorrect OTP       Verification         ✅ Implemented P1
                                     rejected                            

  AUTH-08        Expired OTP         Verification         ✅ Implemented P1
                                     rejected                            

  AUTH-09        Reuse OTP after     Reuse rejected       ✅ Implemented P1
                 success                                                 

  AUTH-10        Exceed OTP attempts Further attempts     ✅ Implemented P1
                                     blocked                             

  AUTH-11        Resend OTP during   Resend restricted    ✅ Implemented P1
                 cooldown                                                

  AUTH-12        Token request       Token issuance       ✅ Implemented P1
                 before required     denied                              
                 MFA/challenge                                           
                 verification                                            

  AUTH-13        Challenge expiry    Expired/reused       ✅ Implemented P1
                 and single use      challenge rejected                  

  AUTH-14        Token response      Required fields      🟡 Partially   P1
                 contract and secret present; secrets     covered /      
                 exclusion           excluded             verify         
                                                          assertions     
  -------------------------------------------------------------------------------------

## 4. Access Token Validation

  ---------------------------------------------------------------------------------
  ID             Test scenario     Expected result  Status           Priority
  -------------- ----------------- ---------------- ---------------- --------------
  TOK-01         Valid token on    Request succeeds 🟡 Partially     P1
                 protected                          covered / verify 
                 endpoint                           endpoint         
                                                    assertions       

  TOK-02         Expired access    Authentication   ⬜ Not verified  P1
                 token             rejected,                         
                                   normally HTTP                     
                                   401                               

  TOK-03         Malformed access  Authentication   ⬜ Not verified  P1
                 token             rejected                          

  TOK-04         Invalid token     Authentication   ✅ Implemented   P1
                 signature         rejected                          

  TOK-05         Invalid           Rejected when    ⬜ Not verified  P1
                 issuer/audience   claims are                        
                                   validated                         

  TOK-06         Missing token on  Authentication   ⬜ Not verified  P1
                 protected         rejected                          
                 endpoint                                            

  TOK-07         Incorrect         Authentication   ⬜ Not verified  P1
                 Authorization     rejected                          
                 header format                                       

  TOK-08         Token after       Authentication   ✅ Implemented   P1
                 session deletion  rejected                          

  TOK-09         Token associated  Authentication   ✅ Implemented   P1
                 with inactive     rejected                          
                 account                                             

  TOK-10         Token associated  Authentication   ✅ Implemented   P1
                 with inactive     rejected                          
                 application                                         

  TOK-11         Revoked access    Authentication   🟡 Partially     P1
                 token             rejected         covered / verify 
                                                    direct           
                                                    assertions       

  TOK-12         Wrong token type  Token rejected   ✅ Implemented   P1
                 on endpoint                                         

  TOK-13         Tampered claims   Token rejected   🟡 Partially     P1
                                                    covered by       
                                                    signature test;  
                                                    verify           
                                                    claim-specific   
                                                    coverage         

  TOK-14         Expiration        Expiration       ⬜ Not verified  P2
                 boundary          handled                           
                                   consistently                      

  TOK-15         Role/permission   Policy enforced  ✅ Implemented   P1
                 enforcement                        for              
                                                    authorization    
                                                    decision paths   
  ---------------------------------------------------------------------------------

## 5. Refresh Token Lifecycle

  -----------------------------------------------------------------------------------
  ID             Test scenario         Expected result  Status         Priority
  -------------- --------------------- ---------------- -------------- --------------
  REF-01         Refresh using valid   New access token ✅ Implemented P1
                 token                 issued and state                
                                       updated                         

  REF-02         Refresh using revoked Request rejected ✅ Implemented P1
                 token                                                 

  REF-03         Expired refresh token Request rejected ✅ Implemented P1

  REF-04         Malformed/invalid     Request rejected 🟡 Partially   P1
                 refresh token                          covered /      
                                                        verify         
                                                        malformed case 

  REF-05         Reuse old token after Replay rejected; ✅ Implemented P1
                 rotation              replacement                     
                                       behavior follows                
                                       policy                          

  REF-06         Refresh token from    Request rejected ✅ Implemented P1
                 another application                                   

  REF-07         Refresh after session Request rejected 🟡 Partially   P1
                 deletion/revocation                    covered /      
                                                        verify each    
                                                        transition     

  REF-08         Refresh for inactive  Request rejected 🟡 Partially   P1
                 account/application                    covered /      
                                                        verify each    
                                                        condition      

  REF-09         Concurrent refresh    No unintended    ⬜ Not         P1
                 requests with same    duplicate valid  verified       
                 token                 token chains                    

  REF-10         Missing refresh token Authentication   ⬜ Not         P1
                                       rejected         verified       

  REF-11         Use refresh token as  Request rejected 🟡 Partially   P1
                 access token                           covered by     
                                                        token-type     
                                                        tests; verify  
                                                        both           
                                                        directions     
  -----------------------------------------------------------------------------------

## 6. Logout, Revocation and Sessions

  -------------------------------------------------------------------------------
  ID             Test scenario   Expected result    Status         Priority
  -------------- --------------- ------------------ -------------- --------------
  SES-01         Signup → login  Lifecycle          ✅ Implemented P1
                 → issue →       completes                         
                 refresh →                                         
                 revoke                                            

  SES-02         Access token    Authentication     ✅ Implemented P1
                 after           rejected                          
                 revocation                                        

  SES-03         Refresh token   Request rejected   ✅ Implemented P1
                 after                                             
                 revocation                                        

  SES-04         Logout without  Documented         ⬜ Not         P1
                 token           error/idempotent   verified       
                                 behavior                          

  SES-05         Logout with     Handled according  ⬜ Not         P1
                 invalid token   to API contract    verified       

  SES-06         Repeat          Idempotent or      ⬜ Not         P2
                 logout/revoke   documented         verified       
                                 response                          

  SES-07         Revoke one      Only intended      ⬜ Not         P1
                 session while   session revoked    verified       
                 another is                                        
                 active                                            

  SES-08         Delete session  Associated access  ✅ Implemented P1
                 from database   token rejected                    

  SES-09         Expired session Session cannot     🟡 Partially   P1
                                 authorize requests covered /      
                                                    verify         
                                                    explicit case  

  SES-10         Revocation      No inconsistent    ⬜ Not         P1
                 fails partway   token/session      verified       
                 through         state                             
  -------------------------------------------------------------------------------

## 7. Password Recovery

  -------------------------------------------------------------------------------
  ID             Test scenario       Expected       Status         Priority
                                     result                        
  -------------- ------------------- -------------- -------------- --------------
  PWD-01         Recovery request    Recovery flow  ✅ Implemented P1
                 for known account   initiated                     

  PWD-02         Recovery request    Account        ✅ Implemented P1
                 for unknown account existence not                 
                                     exposed                       

  PWD-03         Invalid/expired     Request        ✅ Implemented P1
                 recovery challenge  rejected                      

  PWD-04         Reuse completed     Reuse rejected 🟡 Partially   P1
                 recovery challenge                 covered /      
                                                    verify replay  
                                                    assertion      

  PWD-05         Successful password Password       ✅ Implemented P1
                 reset               changes                       
                                     correctly                     

  PWD-06         Use old password    Old password   🟡 Partially   P1
                 after reset         rejected       covered /      
                                                    verify         
                                                    assertion      

  PWD-07         Password reset      Sessions       ✅ Implemented P1
                 invalidates         revoked                       
                 existing sessions   according to                  
                                     policy                        

  PWD-08         Recovery            Requests       ✅ Implemented P1
                 attempts/cooldown   restricted                    
                 limits                                            

  PWD-09         Password            Plaintext      ⬜ Not         P1
                 persistence uses    password not   verified       
                 secure hashing      persisted                     
  -------------------------------------------------------------------------------

## 8. OAuth, RBAC and Application Isolation

  ------------------------------------------------------------------------------------
  ID             Test scenario        Expected result  Status           Priority
  -------------- -------------------- ---------------- ---------------- --------------
  RBAC-01        Valid                Token issued     ✅ Implemented   P1
                 client-credentials   with permitted                    
                 flow                 scope                             

  RBAC-02        Invalid client       Authentication   ✅ Implemented   P1
                 credentials          rejected                          

  RBAC-03        Request unauthorized Rejected or      ✅ Implemented   P1
                 scope                scope limited                     
                                      per contract                      

  RBAC-04        Inactive client      Request rejected ✅ Implemented   P1
                 requests token                                         

  RBAC-05        Assign/evaluate      Decisions follow ✅ Implemented   P1
                 roles and            policy                            
                 permissions                                            

  RBAC-06        Missing permission   Access denied    ✅ Implemented   P1

  RBAC-07        Cross-application    Reference        ✅ Implemented   P1
                 role/permission      rejected                          
                 reference                                              

  RBAC-08        Resource ownership   User cannot      🟡 Partially     P1
                 on protected         access another   covered / verify 
                 endpoints            user's data      endpoint-level   
                                                       enforcement      

  RBAC-09        Disabled             Access denied    🟡 Partially     P1
                 service/scope cannot                  covered / verify 
                 be used                               endpoint         
                                                       enforcement      
  ------------------------------------------------------------------------------------

## 9. Security, Rate Limiting and Audit

  --------------------------------------------------------------------------------------------
  ID             Test scenario               Expected result     Status         Priority
  -------------- --------------------------- ------------------- -------------- --------------
  SEC-01         Production configuration    Unsafe/incomplete   ✅ Implemented P1
                 validation                  config rejected                    

  SEC-02         Missing JWT private key     Configuration       ✅ Implemented P1
                                             validation fails                   

  SEC-03         Missing/short challenge     Configuration       ✅ Implemented P1
                 HMAC secret                 validation fails                   

  SEC-04         Invalid RSA/JWT key         Configuration       ✅ Implemented P1
                 configuration               rejected                           

  SEC-05         Development identity header Request rejected    ✅ Implemented P1
                 prohibited                                                     

  SEC-06         Rate limit by IP            Limit enforced      ✅ Implemented P1

  SEC-07         Rate limit by               Limit enforced      ✅ Implemented P1
                 identifier/account                                             

  SEC-08         Rate-limit retry metadata   Retry information   ✅ Implemented P2
                                             follows policy                     

  SEC-09         Audit events and            Audit logs mask     ✅ Implemented P1
                 sensitive-field masking     sensitive data      for reviewed   
                                                                 cases          

  SEC-10         Secrets excluded from all   Passwords, tokens   🟡 Partially   P1
                 logs/errors                 and OTPs not leaked covered /      
                                                                 expand         
                                                                 failure-path   
                                                                 coverage       

  SEC-11         JWT                         Invalid values      ⬜ Not         P1
                 issuer/audience/algorithm   rejected where      verified       
                 restrictions                required                           

  SEC-12         CORS policy                 Only intended       ⬜ Not         P2
                                             origins/methods     verified       
                                             allowed                            

  SEC-13         Proxy-header trust behavior Spoofed headers     🟡 Partially   P1
                                             cannot bypass       covered /      
                                             policy              verify runtime 
                                                                 behavior       

  SEC-14         No live secrets committed   Repository contains ⬜ Not         P1
                 to repository               no live secrets     verified       

  SEC-15         HMAC challenge              Invalid/replayed    🟡 Partially   P1
                 tampering/replay            challenge rejected  covered /      
                                                                 verify         
                                                                 dedicated      
                                                                 cases          
  --------------------------------------------------------------------------------------------

## 10. Email Delivery and External Dependencies

  ------------------------------------------------------------------------------------
  ID             Test scenario           Expected result Status         Priority
  -------------- ----------------------- --------------- -------------- --------------
  MAIL-01        Send email through      Correct request ✅ Implemented P1
                 Brevo HTTPS API         and success                    
                                         handling                       

  MAIL-02        Brevo returns HTTP      Failure handled ✅ Implemented P1
                 error                   safely                         

  MAIL-03        SMTP fallback behavior  Fallback        ✅ Implemented P1
                                         follows                        
                                         configuration                  

  MAIL-04        Provider failure does   Sensitive       🟡 Partially   P1
                 not leak                values excluded covered /      
                 credentials/OTP         from logs       verify all     
                                                         failure paths  

  MAIL-05        Signup                  User journey    ✅ Implemented P1
                 email-verification      behaves                        
                 workflow                correctly                      

  MAIL-06        Recovery/verification   Challenge and   ✅ Implemented P1
                 email workflow          delivery flow                  
                                         behaves                        
                                         correctly                      
  ------------------------------------------------------------------------------------

## 11. API Validation, Reliability and Infrastructure

  ------------------------------------------------------------------------------------------------
  ID             Test scenario        Expected result        Status                 Priority
  -------------- -------------------- ---------------------- ---------------------- --------------
  API-01         Missing required     Documented validation  ⬜ Not verified        P1
                 fields               response                                      

  API-02         Wrong field          Request rejected       ⬜ Not verified        P1
                 types/malformed JSON safely                                        

  API-03         Unknown endpoint     HTTP 404               ⬜ Not verified        P2

  API-04         Unsupported HTTP     HTTP 405 where         ⬜ Not verified        P2
                 method               applicable                                    

  API-05         Unexpected internal  Safe 5xx; no sensitive ⬜ Not verified        P1
                 exception            detail leaked                                 

  API-06         Response             Contract consistent    🟡 Partially covered / P1
                 schema/status        across endpoints       verify                 
                 contract                                    endpoint-by-endpoint   

  API-07         Database transaction No                     ⬜ Not verified        P1
                 failure              partial/inconsistent                          
                                      state                                         

  REL-01         Health endpoint      Correct service health ✅ Implemented         P2
                                      response                                      

  REL-02         Readiness endpoint   Dependency/readiness   ✅ Implemented         P2
                                      state correct                                 

  REL-03         PostgreSQL migration Migrations complete    ✅ Implemented         P1
                 tests                successfully                                  

  REL-04         Fixture teardown     No cross-test leakage  🟡 Partially covered / P1
                 cleans                                      verify teardown        
                 overrides/DB/cache                          behavior               

  REL-05         Run tests in         Results remain         ⬜ Not verified        P2
                 different orders     consistent                                    

  REL-06         Parallel test        No shared-state        ⬜ Not verified        P2
                 execution            collisions                                    

  REL-07         Full test suite      Stable                 🟡 Historical: 87      P1
                                      pass/skip/failure      passed, 1 skipped;     
                                      results                rerun required         

  REL-08         Line and branch      Critical security      ⬜ Not verified        P2
                 coverage             paths covered                                 
  ------------------------------------------------------------------------------------------------

## 12. Recommended Implementation Order

  ---------------------------------------------------------------------------
  Order             Scenario           Reason               Status
  ----------------- ------------------ -------------------- -----------------
  1                 TOK-02 --- Expired No explicit case     ⬜ Next
                    access token       identified in        
                                       reviewed token files 

  2                 TOK-03 ---         Complements          ⬜ Pending
                    Malformed access   signature and        
                    token              token-type tests     

  3                 TOK-06 --- Missing Confirms             ⬜ Pending
                    access token       protected-endpoint   
                                       behavior             

  4                 TOK-07 ---         Validates header     ⬜ Pending
                    Malformed          parsing              
                    Authorization                           
                    header                                  

  5                 SES-07 ---         Ensures revocation   ⬜ Pending
                    Multiple-session   targets the intended 
                    isolation          session              

  6                 REF-09 ---         Covers race          ⬜ Pending
                    Concurrent refresh conditions in token  
                    requests           rotation             

  7                 PWD-09 ---         Verifies secure      ⬜ Pending
                    Password hash      credential storage   
                    persistence                             

  8                 SEC-10 ---         Extends masking      ⬜ Pending
                    Sensitive data     checks across flows  
                    leakage                                 

  9                 API-07 ---         Checks consistency   ⬜ Pending
                    Database           during failures      
                    transaction                             
                    failure                                 

  10                REL-05/06 ---      Improves suite       ⬜ Pending
                    Order independence reliability          
                    and parallel                            
                    execution                               
  ---------------------------------------------------------------------------

## 13. Coverage Maintenance Rules

1.  Inspect existing tests before adding new ones.
2.  Mark a scenario **Implemented** only after verifying the test and
    its relevant assertions.
3.  Use **Partially covered / verify assertions** when a related test
    exists but does not prove the entire expected behavior.
4.  Use **Not verified** when available evidence is insufficient. Mark
    **Not implemented** only after confirming absence from the complete
    current suite.
5.  Run the targeted test after each change, then the relevant module
    and full suite at suitable checkpoints.
6.  Record test filename and result as each scenario is completed.
7.  Assert HTTP responses and relevant security/business state where
    applicable.
8.  Treat behavior not required by the current product contract as a
    proposed requirement, not an automatic test failure.

------------------------------------------------------------------------

**Next task:** Implement and verify `TOK-02 — Expired access token`.
Update its status after the test passes, then move to the next scenario.
