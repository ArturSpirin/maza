## Maza

This project is heavily based on the [RSF](https://github.com/threat9/routersploit) 
(RouterSploit Framework) and really all of the credit goes to the Threat9 team and the contributors of the RSF 
for creating the exploits and making them open source. I just wrote two lines of code to scan the network 
and then run their vulnerability scans.

So what this framework does:
1. Checks all of the available exploits and makes a note of which service ports we can potentially hack
2. Scans your network for devices with those open ports
3. Runs suitable vulnerability scans (not attacks, just scans) against those devices

This was a weekend project and I'm not sure how far I'll take it.
So far you can run it like this:
```commandline
python3 maza_scan.py --network="192.168.0.1/24" --threads=500
``` 
or like this:
 ```commandline
python3 maza_scan.py
```
If you do it the second way, I would recommend to have only 1 network interface/adapter.
Otherwise if you happen to have a VM network adapter configured for `169.254.0.0/16`, it may take a while to scan :)

I'm thinking of running this on a Raspberry Pi and some of the things I want to add:

- [ ] Improve console output
- [ ] Continues monitoring mode for open networks
- [ ] Auto connect to open networks that have not yet been scanned
- [ ] Collect metrics on exploits (which ones are more successful then others) 
- [ ] Add caching
- [ ] Add report generation in HTML format
- [ ] Add attack mode

I have tested this only on Windows so far but it should run on Linux as well.