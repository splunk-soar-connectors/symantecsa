[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Security Analytics

Publisher: Splunk  
Connector Version: 2\.1\.5  
Product Vendor: Symantec  
Product Name: Security Analytics  
Product Version Supported (regex): "8\.2\.\*"  
Minimum Product Version: 5\.1\.0  

This app allows querying network traffic details on Symantec Security Analytics \(formerly known as BlueCoat Solera\)

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Security Analytics asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device\_ip** |  required  | string | Device IP \(e\.g\. 127\.127\.127\.127\)
**username** |  required  | string | Username
**api\_key** |  required  | password | API key
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[get pcap](#action-get-pcap) - Queries to return specific network traffic information  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get pcap'
Queries to return specific network traffic information

Type: **investigate**  
Read only: **True**

This action will create a pcap file of network data and upload it to the vault\. Timespan must be in specified format\. Please note that the <b>name</b> of the file in the vault will be stored in such format\: \(filename provided in the parameter\) \(action run timestamp\)\.<br>The <b>filter</b> parameter of <b>get\_pcap</b> accepts queries in the following format\:<br><ul><li>Key\-value pairs are separated by '/'<br>e\.g\. <b>application\_group="file server"</b> can be written as <b>/application\_group/file server</b></li><li>Two regular expression characters are supported \: <ul><li>question mark\('?'\)\- single character</li> <li>asterisk\('\*'\)\- zero or more characters</li></ul></li><li>Logical operators like 'OR', 'AND', 'NOT' are supported</li><li>Along with '=', following operators are used '\!=', '>', '>=', '<', '<=' in custom query as '\_not\_', '\_gt\_', '\_ge\_', '\_lt\_', '\_le\_' respectively</li><li>Contains\('~'\) and not contains\('\!~'\) can also be used <br>e\.g\. <b>ip\_protocol~t</b> which means "ip\_protocol contains char 't'",  can be written as <b>/ip\_protocol/\*t\*</b> </li><li>Complex queries can be created using escaped curly brackets\('/\}'\) and escaped square brackets\('/\]'\) <br>e\.g\. <b>\(application\_id=arp and \(port>50000 or country\!=china\)\)</b> can be written as <b>/\{/\[/application\_id/arp/and/\[/port/\_gt\_50000/or/country/\_not\_china/\]/\]/\}</b> </li><li>Range entries can be used to filter data <br>e\.g\. <b>packet\_length=10\-100</b> can be written as <b>/packet\_length/10\_to\_100</b> </li><li>For more details visit <a href="https\://origin\-symwisedownload\.symantec\.com/resources/webguides/security\_analytics/7\.3\.2/webguide/desktop/ENG/Analytics/Filtering/wildcards\_and\_logical\_operators\.htm" target="\_blank">this link</a></li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  required  | Start of timespan \(YYYY\-mm\-ddTHH\:MM\:SS\) | string | 
**end\_time** |  required  | End of timespan \(YYYY\-mm\-ddTHH\:MM\:SS\) | string | 
**filename** |  required  | Name for PCAP file to be downloaded | string |  `file name` 
**filter** |  required  | Capture filter to apply to PCAP \(Custom Query\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.filename | string |  `file name` 
action\_result\.parameter\.start\_time | string | 
action\_result\.data\.\*\.download\_file | string | 
action\_result\.data\.\*\.filesize | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 