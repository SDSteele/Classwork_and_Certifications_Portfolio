Gobuster

a tool such as ffuf or GoBuster to perform this directory enumeration.

Directory/File Enumeration
irectory (and file) brute-forcing modes specified with the switch dir. Let us run a simple scan using the dirb common.txt wordlist

gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

An HTTP status code of 200 reveals that the resource's request was successful, while a 403 HTTP status code indicates that we are forbidden to access the resource. A 301 status code indicates that we are being redirected, which is not a failure case. 

https://en.wikipedia.org/wiki/List_of_HTTP_status_codes

 identifies a WordPress installation at /wordpress. WordPress is the most commonly used CMS (Content Management System) and has an enormous potential attack surface.
 
 http://10.10.10.121/wordpress in a browser reveals that WordPress is still in setup mode, which will allow us to gain remote code execution (RCE) on the server.
 
 DNS Subdomain Enumeration

There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited. We can use GoBuster to enumerate available subdomains of a given domain using the dns flag to specify DNS mode.

 clone the SecLists GitHub repo, which contains many useful lists for fuzzing and exploitation:

Install SecLists
Web Enumeration

PortMortem@htb[/htb]$ git clone https://github.com/danielmiessler/SecLists

 Web Enumeration

PortMortem@htb[/htb]$ sudo apt install seclists -y

Next, add a DNS Server such as 1.1.1.1 to the /etc/resolv.conf file. We will target the domain inlanefreight.com, the website for a fictional freight and logistics company.

gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

Web Enumeration Tips
Banner Grabbing / Web Server Headers

Web server headers provide a good picture of what is hosted on a web server. They can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured.

use cURL to retrieve server header information from the command line. cURL is another essential addition to our penetration testing toolkit, and familiarity with its many options is encouraged.

curl -IL https://www.inlanefreight.com

Another handy tool is EyeWitness, which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.

Whatweb
We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb. This information can help us pinpoint the technologies in use and begin to search for potential vulnerabilities.

PortMortem@htb[/htb]$ whatweb 10.10.10.121

http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]

Whatweb is a handy tool and contains much functionality to automate web application enumeration across a network.


PortMortem@htb[/htb]$ whatweb --no-errors 10.10.10.0/24

http://10.10.10.11 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.11], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
http://10.10.10.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[File Sharing Service]
http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
http://10.10.10.247 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@cross-fit.htb], Frame, HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.247], JQuery[3.3.1], PHP[7.4.12], Script, Title[Fine Wines], X-Powered-By[PHP/7.4.12], X-UA-Compatible[ie=edge]

Certificates

SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use.
viewing the certificate reveals the details below, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

Robots.txt

It is common for websites to contain a robots.txt file
 purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing
 
  robots.txt file can provide valuable information such as the location of private files and admin pages. In this case, we see that the robots.txt file contains two disallowed entries.
  disallow: /private
  disallow: /upload_files
  
  Navigating to http://10.10.10.121/private in a browser reveals a HTB admin login page.
 
 Source Code
 It is also worth checking the source code for any web pages we come across. We can hit [CTRL + U] to bring up the source code window in a browser.
 This example reveals a developer comment containing credentials for a test account, which could be used to log in to the website.
 
 94.237.122.241:43770
 
 looking at hte ip given in a browser we open the source and find nothing, the main page is a blog for htb but it's only got the intro
we can then use robots.txt and find /admin-login-page.php

in the page source we find: <!-- TODO: remove test credentials admin:password123 -->

found the flag

HTB{w3b_3num3r4710n_r3v34l5_53cr375}

curl -IL 94.237.122.241:43770
HTTP/1.1 200 OK
Date: Thu, 09 Oct 2025 12:31:01 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8

curl -IL 94.237.122.241:43770
HTTP/1.1 200 OK
Date: Thu, 09 Oct 2025 12:31:01 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8

┌──(kali㉿kali)-[~]
└─$ whatweb --no-errors 94.237.122.241:43770
http://94.237.122.241:43770 [200 OK] Apache[2.4.41], Country[FINLAND][FI], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[94.237.122.241], Title[HTB Academy]

gobuster dir -u http://94.237.122.241:43770 -w /usr/share/seclists/Discovery/Web-Content/common.txt



 
 
 
 
 
 
 
 
 
