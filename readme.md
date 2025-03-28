# Xray-CVE-Blacklist
This repo lists the bloked CVE to add in the Xray policies.  
DDS manages Xray with three different global rules applied on every project artifacts repository as follows :  
  
-> A global security watch is applied on every repo and is containing :
  1. a blocking policy with :  
    A. a rule on malicious packages discovered by Xray Hunters Team  
    ~~B. a rule on CVEs with CVSS>9 and EPSS > 0,7 (exept for lifted perimeters*)~~ 
  2. a non blocking policy (until july 2025) with :  
    ~~C. a rule on CVEs with CVSS between 4 and 9 and EPSS > 0,9~~
  
~~The B and C rules correspond respectively to the black and red zone indicated below.~~

**Update :**

**- There is no longer a distinction between the black and red zones; both have been merged into a common blacklist.**

**- EPSS Version 4 was released on March 17th, 2025. As part of the data modeling refinement process, CVEs with high EPSS scores have seen a significant decrease, resulting in the final blacklist reducing from approximately 4,000 CVEs to around 2,500 CVEs**

The corresponding CVE BlackList can be found in this SGitHub repo in the CVE_Black_List directory : https://github.com/lazbord/xray-scanner-cvss-psse/tree/main/CVE_Black_List

**The following text is outdated and kept only for data preservation purposes.**
  
Lifted perimeters are not blocked by the rules when migrating and have a 3 moths grace period on all of their vulnerable artifacts detected by Xray when migrating.  

## Blacklist thresholds
![image](https://sgithub.fr.world.socgen/storage/user/55836/files/d00c9069-5e8d-4cdd-8840-55e585d72697)

## Blocking strategy
![image](https://sgithub.fr.world.socgen/storage/user/55836/files/4814bff2-23ee-42b8-a1c1-dc03903175ac)  
