## Maza

---

This project is heavily based on the RSF (RouterSploit Framework) and really all 
of the credit goes to the Threat9 team and the contributors of the RSF for creating the 
exploits and making them open source. I just wrote two lines of code to scan the network 
and then run their vulnerability scans.

So what this framework does:
1. Checks all of the available exploits and makes a note of which service ports we can potentially hack
2. Does a network scan for devices on your network
3. Does a port scan on the devices (Only for those ports that we can potentially hack)
4. Runs the vulnerability scan (Only the ones that are suitable for the open ports we found)
5. It does not run the exploits. Yet . . .

This was a weekend project and I just barely got it up and running. 
So bunch of work still to be done in terms of code & performance optimization, arg options and 
who knows what else. In fact there is bunch of stuff that is hard coded right now so it won't 
run on your machine. Speaking of machines, this does run on Windows as well as Linux.