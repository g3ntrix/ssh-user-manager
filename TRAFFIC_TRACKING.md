# SSH User Manager - Traffic Tracking Info

## How Traffic Tracking Works

The script uses **iptables** to track network traffic per user (by UID).

### Important Notes:

1. **Traffic shows 0 initially** - This is normal. Traffic only accumulates when:
   - The user is logged in via SSH
   - The user actively uses the connection (browsing, downloading, etc.)

2. **What gets tracked:**
   - Outbound traffic (OUTPUT chain) from processes owned by the user
   - This includes SSH tunnel traffic if processes run as that user

3. **Limitations:**
   - If you're using SSH as a SOCKS proxy or port forwarding, traffic might not be attributed correctly
   - iptables counters reset on reboot (consider using iptables-persistent)
   - Traffic from root or other users won't be counted for the specific user

### To Test Traffic Tracking:

1. SSH into your VPS as the created user:
   ```bash
   ssh komar@your-vps-ip
   ```

2. Generate some traffic (as that user):
   ```bash
   # Download a test file
   wget http://speedtest.tele2.net/1MB.zip
   
   # Or
   curl -O http://speedtest.tele2.net/10MB.zip
   ```

3. Check traffic from the manager:
   ```bash
   sudo ./ssh-user-manager.sh
   # Select option 8 (View traffic usage)
   ```

### To Make iptables Rules Persistent:

On Debian/Ubuntu:
```bash
apt-get install iptables-persistent
netfilter-persistent save
```

### Alternative Traffic Tracking:

For more accurate SSH tunnel traffic tracking, consider:
- **vnstat** - Network traffic monitor
- **Bandwidth monitoring tools** like `iftop` or `nethogs`
- Custom accounting with `tc` (traffic control)

### Checking iptables Rules:

To see if rules are properly set up:
```bash
iptables -L OUTPUT -v -n
```

You should see lines like:
```
pkts bytes target     prot opt in out source    destination
   0     0 ACCEPT     all  --  *  *   0.0.0.0/0 0.0.0.0/0  owner UID match 1001
```
