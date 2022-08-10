# fdns
Dataplane.org DNS server daemon

fdns is a minimal DNS server daemon.  It listens on TCP and UDP port 53,
as well as on IPv4 and IPv6 local addresses.  It logs all incoming DNS
query messages to syslog.

**WARNING** When listening on a non-wildcard IPv6 address during system
start up, this daemon may cause high CPU utilization due to a race
condition with IPv6 duplicate address detection (DAD).  Restarting the
daemon will fix the problem.  A more permanent work-around is to either
disable DAD on IPv6 interface(s) or delay daemon loading until DAD has
had time to complete.
