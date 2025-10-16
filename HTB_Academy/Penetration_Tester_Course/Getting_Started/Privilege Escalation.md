learning about metasploit here some

we can not only use more advanced search filters, but when we find a vulnerability we can use “show options” to find out what info is needed and what is a required to run the vulnerability

also we can use the “check” cmd to check if the vuln will work! how useful!

here are many retired boxes on the Hack The Box platform that are great for practicing Metasploit. Some of these include, but not limited to:

Granny/Grandpa
Jerry
Blue
Lame
Optimum
Legacy
Devel

also learned searchsploit

search exploit eternalblue

use exploit/windows/smb/ms17_010_psexec

see what we can do here and we need so do show options cmd

given a machine and told to use what we've learned to do it

94.237.122.241:55098

Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start) 

tried out autoscan and rustscan this time, lots of open ports

putting it in a web browser pulls up a getting started wordpress site

let's try ssh since I know it fairly well

using metasploit

tried the ldp first, see what works

well tried ssh first and no luck there

ldp didn't work

maybe if i wasn't an idiot and listend i'd know ot use port 55098 and find an apache httpd 2.4.41 attached. ugh

and the website wordpress...ughhhhh

at least online i'm not hte only one who spent too much time overthinking it and search ports

so we start using metasploit with vuln 0 = simple backup file read

the site says “This plugin will create a directory in the root of your WordPress directory called ‘simple-backup’ to store the backup files.”

and using this we can get it to pull files, we see that we can do flag.txt to get the flag!

Lessons Learned: It’s Not Always Rocket Science

    Start with the basics: If there’s an address or port, just open it in a browser.
    Be methodical: Cybersecurity is like solving a puzzle—piece by piece.
    Laugh at your mistakes: They’re part of the process (and the fun).



