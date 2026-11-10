LEAVE RECORDS (private logins, SQLite database)

Needs Node.js 22.13 or newer (Node 24 is fine). Nothing else to install.

Run
  node server.js        (or: npm.cmd start)
The terminal prints two addresses:
  http://localhost:3000            (this computer)
  http://192.168.x.x:3000          (colleagues on the same Wi-Fi or LAN)

Optional invite code, so only your colleagues can create accounts:
  Windows PowerShell:  $env:REGISTER_CODE="mycode"; node server.js
  Mac or Linux:        REGISTER_CODE=mycode node server.js

Notes
- Data is saved in leave.db in this folder. Back up this file regularly.
- The server must keep running, on a computer that stays on, for others to use it.
- If colleagues cannot connect, allow Node.js through the Windows firewall for private networks.
- Traffic on the network is not encrypted (plain http). Use it only on a network you trust.
- A warning about SQLite being experimental may appear when it starts. It is harmless.

Forgot password: node reset-password.js EMPLOYEE_ID NEWPASSWORD (run in this folder, then tell the person to change it).
Your existing leave.db keeps working. Old entries appear under their year, and each year asks for its allowances the first time you open it.
