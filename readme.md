LazyTunnel
==========

Lazily and automatically forward localhost ports to services running on AWS ec2.

Usage
-----
run `lazytunnel`  and open a browser to localhost on the appropriate port.

What This Tool Does
-------------------
* Open a port on the local machine for each service.
* On connection, lookup the list of ec2 instances that can handle the connection by ec2 tag.
* uploads a new ssh key to use on aws that lasts 60 seconds.
* connects to the ec2 instance automatically over ssh
* Forwards any connections from the local machine to an ec2 instance on the same port.

What This Tool Replaces
-----------------------
* to port forward web traffic to a set of ec2 instances
* lookup the ec2 instance by name or "role" tag  in AWS console
* copy the ip address into a terminal
* grab the correct ssh key for the instance
* run `ssh -i <keypath> ec2-user@<ip address> -L port:localhost:port
* ignore the shell I don't care about anymore, but keep it open
* repeat 2 more times for the other 2 services I care about

