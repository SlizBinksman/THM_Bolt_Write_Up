# THM_Bolt_Write_Up
A write up on the Bolt room from TryHackMe.com &amp; re-writing of r3m0t3nu11's PoC exploit script

# CREDITS
I would like to thank the following people below. Analyzing their work such as white papers and PoC scripts made this possible. Without their research & work, i would not have had the resources neccesary to understand what the vulnerabilitys are that make an authenticated remote code execution on the Bolt Content Management System possible. I take NO CREDIT for the original discovery & exploitation of the vulnerabilitys in the application. I did this to better understand the underlying reasons of what made the application vulnerable and how they can be exploited rather than skidding through with the MSF module and calling it a day.

Original Discovery - Sivanesh Ashok | @sivaneshashok | stazot.com  
https://seclists.org/fulldisclosure/2020/Jul/4  

Original PoC Author - r3m0t3nu11  
https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py  
https://www.exploit-db.com/exploits/48296  

MSF Module Author - Erik Wynter | @wyntererik  
https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce/  
https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/bolt_authenticated_rce.rb  

THM Bolt Room Author - 0x9747  
https://tryhackme.com/p/0x9747  
https://tryhackme.com/room/bolt  

# If You See Something, Say Something!
I am by no means a seasoned security professional. This means that i may provide some incorrect information. If you're a seasoned professional/experienced reseacher and you see something that is incorrect, please inform me so i can come back, study up on what i got wrong and provide the correct information. This is beneficial to me as well as other novice researchers that may stumble upon this write up. If you find bad information that i have written, Please contact me at slizbinksman@gmail.com so i can fix it. Thank you!

# The Payload
The payload that we will be using is `<?php system($_GET['sploit']);?>`. I am not a PHP guy and have never written anything in PHP at the time of writing. This is why search engines are awesome! Upon inspection, we can see what looks to be a system call to some kind of variable. This payload is a PHP webshell in its most simple form. The `system()` call in PHP will both execute and return the output of any command on the system hosting the CMS. The PHP `$_GET[""]` allows us to retrieve a specified value from a URL in an HTTP GET request. At line 135 in the python script, We have the following code: `sendCommand = requests.get(f'{args.URL}/files/{file}.php?sploit={command}')`. Notice that torwards the end of the URL in the `requests.get()` call, We see the word `sploit`. When we retrieve sploit with the `$_GET[""]` variable, The variable will obtain the value of whatever value you set sploit to be via the get request. In this case, by passing `$_GET["sploit"]` into the `system()` call, We are able to take the value of sploit from the request and execute that on the system hosting Bolt CMS.

# The Vulnerability
**1. XSS (Cross Site Scripting)**

In section 3 of Sivanesh's disclosure, Sivanesh describes how the user input that allows you to change the display name of your profile is vulnerable to Stored XSS. Stored XSS is when a malicious code injection becomes part of the webservers code itself hence why it is also described as Persistent XSS. The reason for the vulnerability is because of a condition in which the users input does not get encoded. When the unencoded display name appears in the system log, it is displayed in plain text. As an attacker, This allows us to use HTML tags to execute arbitrary code as an admin or developer since the default configuration of the CMS allows those two roles to access the system log. By slapping the HTML php tag `<?php;?>` around `system($_GET['sploit'])`, We are able to tell the webserver to to execute system commands that get passed through the the parameter obtained by the `$_GET` from the HTTP GET request utilizing PHP.

![image](https://user-images.githubusercontent.com/90923369/140625420-d02686f1-6091-429e-9946-06a120d67af2.png)

![image](https://user-images.githubusercontent.com/90923369/140625527-a0dfb9ea-c51f-46cf-82b0-05082869033e.png)

![image](https://user-images.githubusercontent.com/90923369/140625658-543531b4-477a-4c4d-9c83-2718deaef2ff.png)

As you can see above, we have successfully changed our display name to the PHP payload. The next task is to access the payload to enable execution. Our payload will be stored in the /async/browse/cache/.sessions directory as a session token. The session token contains information about the session such as username, password & our display name which contains the payload. 

![image](https://user-images.githubusercontent.com/90923369/140626506-6eae02d5-1a22-40b0-8ac4-87dcc6b3b077.png)

As you can see, we have a bunch of session tokens. The issue is that we cant execute our PHP payload without the correct file extension. This is where the next vulnerability comes in. In section 4 of Sivanesh's disclosure, Sivanesh describes how we can abuse the CMS's method of sanitization to rename files on the webserver. The disclosure states that we need to add `/.` to the end of the filename to be able to trick the the validation functions into allowing the php file extension. You'll notice that in r3m0t3nu11's original PoC exploit that there is no `/.` in front of the "newname" parameter when we rename the session tokens but we do have code that allows us to traverse backwards through the directorys `../`. I played around with this for a little bit and found that if dont we have the directory traversal markings in the back of `/public/files/`, then the file will not be renamed successfully. I assume this is because we need to move 3 directorys back from the parent directory which is `/app/cache/.sessions` hence why the newname parameter contains 3 `../` directory markings. An interesting thing that i found was that we are able to successfully rename the session token with the php extension with or without the `/.` marking in front of the newname parameter like this `../../../public/files/sploit.php/.` but if we remove the directory traversal markings like this `/public/files/sploit.php/.` and then try to rename the file, it will fail. When we have the correct token containing our payload renamed with the extension, we will be able to use the URL parameter we specified earlier to pass our commands to payload which will then be executed on the server hosting the CMS. The renamed file will be in the /public/files directory hence our command injection URL `/files/sploit.php?sploit=`. At this point, we can start making GET requests to the file and passing in our commands to the sploit parameter to be executed by our payload!

# THM Bolt Write Up

So to start off, We will perform an Nmap scan to get a layout of our attack surface.

![image](https://user-images.githubusercontent.com/90923369/140658580-01f06ff1-725d-4fa5-a6cf-488b936ad475.png)

We can see that we have 4 services listening, 3 of which are accessible. SSH, HTTP, and the CMS are running on 22, 80 and 8000 respectivley. It seems like the DNS (Port 53) port is behind a firewall so theres not much we can do there. Moving on, we will now attempt to connect to the HTTP server and see if anything useful is hosted there!

![image](https://user-images.githubusercontent.com/90923369/140658709-9233dda7-0590-44e6-847d-a194d0afd858.png)

It looks like we have a default page for the apache2 hosting system. There's nothing useful here. Next we will connect to port 8000 where the CMS is being hosted.

![image](https://user-images.githubusercontent.com/90923369/140658781-9e4623f1-b121-47de-b760-54aaa79eb277.png)

When we connect to port 8000, we can confirm that this is where the CMS is being hosted. When we look around, we can find a message from one of the admins that gives us his username and password. On my first go around, i tried using the credentials to connect to the server over Secure Shell but it was only a rabbit hole that lead nowhere useful. The next step would be to find a login page for the CMS and see if it works there!

![image](https://user-images.githubusercontent.com/90923369/140659093-02a53c6f-ab79-4113-8a4c-c4d9a74be313.png)

By navigating to /bolt/login, we are presented with an authentication page. When we try to log in with the credentials that we found.......

![image](https://user-images.githubusercontent.com/90923369/140659162-01930860-4840-4789-91a7-0f30efb0ed13.png)

Boom! we're in the system. The next thing to would be to find the version of this CMS.

![image](https://user-images.githubusercontent.com/90923369/140659285-621483bd-9e51-4e48-aaa9-a724837107e1.png)

By hitting f12 and opening the developer tools, we are presented with the version of Bolt that we are currently working with. In this case it is version 3.7.1. We can now run searchsploit and see if anything comes up to exploit this version of bolt.

![image](https://user-images.githubusercontent.com/90923369/140659428-1999dace-65d5-46a3-b6bb-8bb9f820db87.png)

When we get our results from searchsploit, we can see that there is an authenticated RCE available on exploit DB. I also chose to search metasploit to show that one exists as well. The issue with the r3m0t3nu11 exploit DB script is that there is an encoding issue with the "BOLT CMS" banner. When i began testing the script to find out how it works in action, i was able to get the script to work by removing the banner outright. For this write up though, I will use the re-write script i wrote that is based off of r3m0t3nu11s original PoC.

![image](https://user-images.githubusercontent.com/90923369/140660833-428e9f0a-6872-4c54-ae19-b28b0ccaec45.png)

Once we have a command shell on the target system, we can see that we are running as root! Our shell lives in the public files directory because that is where it was saved after the token was renamed to contain our file extention to execute the payload hidden inside!

An interesting tidbit of inforamtion!

![image](https://user-images.githubusercontent.com/90923369/140658173-07f1fdf7-5f36-43f5-8a41-100b7a8b8cc5.png)

If we use the raw ouput option, we can then view information held inside the renamed session token. We can see information such as our username, password hash and our display name where our payload is being held!

# Thank You!
Thank you for taking the time to read through this. This is the first write up i have ever done. As stated above, All credit goes to the people listed in the credits section. It was very interesting to go beyond msf and exploit DB to find out how this vulnerability could be abused. If you notice any incorrect information, please reach out to me so i can go back and fix it. Again, Thank you!
