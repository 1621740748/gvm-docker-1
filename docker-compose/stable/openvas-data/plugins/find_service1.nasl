###############################################################################
# OpenVAS Vulnerability Test
#
# Service Detection with 'GET' Request
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17975");
  script_version("2021-06-18T12:11:02+0000");
  script_tag(name:"last_modification", value:"2021-06-18 12:11:02 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'GET' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service_spontaneous.nasl",
                      "cifs445.nasl", "apache_SSL_complain.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'GET' request
  to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("string_hex_func.inc");
include("global_settings.inc");
include("dump.inc");
include("sip.inc");

if( ! port = get_kb_item( "Services/unknown" ) )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

k = "FindService/tcp/" + port + "/get_http";
r = get_kb_item( k + "Hex" );
if( strlen( r ) > 0 )
  r = hex2raw( s:r );
else
  r = get_kb_item( k );

r_len = strlen( r );
if( r_len == 0 ) {
  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' );
  r = recv( socket:soc, length:4096 );
  close( soc );

  r_len = strlen( r );
  if( r_len == 0 ) {
    debug_print( 'Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n' );
    exit( 0 );
  }

  set_kb_item( name:k, value:r );
  rhexstr = hexstr( r );
  if( '\0' >< r )
    set_kb_item( name:k + "Hex", value:rhexstr );
} else {
  rhexstr = hexstr( r );
}

rbinstr_space = bin2string( ddata:r, noprint_replacement:' ' );
rbinstr_nospace = bin2string( ddata:r );

# aka HTTP/0.9
if( r =~ '^[ \t\r\n]*<HTML>.*</HTML>' ) {
  service_report( port:port, svc:"www", banner:r );
  exit( 0 );
}

if( r == '[TS]\r\n') {
  service_report( port:port, svc:"teamspeak-tcpquery", banner:r );
  exit( 0 );
}

if( r == 'gethostbyaddr: Error 0\n' ) {
  service_register( port:port, proto:"veritas-netbackup-client", message:"Veritas NetBackup Client Service is running on this port" );
  log_message( port:port, data:"Veritas NetBackup Client Service is running on this port" );
  exit( 0 );
}

if( "GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r ||
    "GET/HTTP/1.0 : ERROR : INVALID-PORT" >< r ) { # nb: Some auth services on e.g. Windows are responding with such a different response
  service_report( port:port, svc:"auth", banner:r );
  exit( 0 );
}

if( 'Host' >< r && 'is not allowed to connect to this' >< r && ( "mysql">< tolower( r ) || "mariadb" >< tolower( r ) ) ) {
  if( "mysql">< tolower( r ) ) {
    text = "A MySQL";
  } else if( "mariadb" >< tolower( r ) ) {
    text = "A MariaDB";
  } else {
    text = "A MySQL/MariaDB";
  }
  service_register( port:port, proto:"mysql", message:text + " server seems to be running on this port but it rejects connection from the scanner." ); # or wrapped?
  log_message( port:port, data:text + " server seems to be running on this port but it rejects connection from the scanner." );
  exit( 0 );
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if( "Host" >< r && " is blocked " >< r && "mysqladmin flush-hosts" >< r ) {
  service_register( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  log_message( port:port, data:"A MySQL server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  exit( 0 );
}

#0x00:  4A 00 00 00 0A 35 2E 37 2E 31 36 00 68 49 72 00    J....5.7.16.hIr.
#0x10:  6A 5F 26 1F 4A 52 20 5B 00 FF FF 08 02 00 FF C1    j_&.JR [........
#0x20:  15 00 00 00 00 00 00 00 00 00 00 50 4D 51 64 16    ...........PMQd.
#0x30:  3D 50 19 35 1E 48 46 00 6D 79 73 71 6C 5F 6E 61    =P.5.HF.mysql_na
#0x40:  74 69 76 65 5F 70 61 73 73 77 6F 72 64 00 1B 00    tive_password...
#0x50:  00 01 FF 84 04 47 6F 74 20 70 61 63 6B 65 74 73    .....Got packets
#0x60:  20 6F 75 74 20 6F 66 20 6F 72 64 65 72              out of order

# or

#0x00:  3E 00 00 00 0A 35 2E 31 2E 37 31 2D 63 6F 6D 6D    >....5.1.71-comm
#0x10:  75 6E 69 74 79 00 17 ED 1F 00 29 64 41 55 68 2E    unity.....)dAUh.
#0x20:  46 58 00 FF F7 08 02 00 00 00 00 00 00 00 00 00    FX..............
#0x30:  00 00 00 00 00 69 25 7A 59 31 26 67 58 61 5D 33    .....i%zY1&gXa]3
#0x40:  24 00 1B 00 00 01 FF 84 04 47 6F 74 20 70 61 63    $........Got pac
#0x50:  6B 65 74 73 20 6F 75 74 20 6F 66 20 6F 72 64 65    kets out of orde
#0x60:  72                                                 r

# SphinxQL of the Sphinx search server is responding with something like the following below
# which would make this detection to wrongly detect a SphinxQL service as MySQL.
#
# 3.0.2 e3d296ef@190531 release
#
# 0x00:  61 00 00 00 0A 33 2E 30 2E 32 20 65 33 64 32 39    a....3.0.2 e3d29
# 0x10:  36 65 66 40 31 39 30 35 33 31 20 72 65 6C 65 61    6ef@190531 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 08 00 15 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 6D    ...............m
# 0x50:  79 73 71 6C 5F 6E 61 74 69 76 65 5F 70 61 73 73    ysql_native_pass
# 0x60:  77 6F 72 64 00                                     word.
#
if( rbinstr_space !~ "[0-9.]+ [0-9a-z]+@[0-9a-z]+ release" &&
    ( ( "mysql_native_password" >< r && "Got packets out of order" >< r ) ||
        "001b000001ff8404476f74207061636b657473206f7574206f66206f72646572" >< rhexstr ||
        "006d7973716c5f6e61746976655f70617373776f726400" >< rhexstr ) ) {
  service_register( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port." );
  log_message( port:port, data:"A MySQL/MariaDB server seems to be running on this port." );
  exit( 0 );
}

# JNB30........
# .4....I.n.v.a.l.i.d. .r.e.q.u.e.s.t.:. . .i.n.v.a.l.i.d. .j.n.b.b.i.n.a.r.y.
# [...]
if( r =~ "^JNB30" && ord( r[5] ) == 14 && ord( r[6] == 3 ) ) {
  service_register( port:port, proto:"jnbproxy", message:"ColdFusion jnbproxy is running on this port." );
  log_message( port:port, data:"ColdFusion jnbproxy is running on this port." );
  exit( 0 );
}

if( "Asterisk Call Manager" >< r ) {
  service_register( port:port, proto:"asterisk", message:"An Asterisk Call Manager server is running on this port." );
  log_message( port:port, data:"An Asterisk Call Manager server is running on this port." );
  exit( 0 );
}

# Taken from find_service2
if( r_len == 3 && ( r[2] == '\x10' || # same test as find_service
                   r[2] == '\x0b' ) ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' ) {
  service_register( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 ..
if( (r_len == 5 || r_len == 6) && r[3] == '\0' &&
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0' ) {
  service_register( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

if( r == '\x01Permission denied' || ( "lpd " >< r && "Print-services" >< r )  ) {
  service_report( port:port, svc:"lpd", message:"An LPD server is running on this port" );
  log_message( port:port, data:"An LPD server is running on this port" );
  exit( 0 );
}

#### Double check: all this should be handled by find_service.nasl ####

if( r == 'GET / HTTP/1.0\r\n\r\n' ) {
  service_report( port:port, svc:"echo", banner:r );
  exit( 0 );
}

# Should we excluded port=5000...? (see find_service.c)
if( r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ' ) {
  service_report( port:port, svc:"www", banner:r );
  exit( 0 );
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if( r =~ '^[0-9][0-9][0-9]-?[ \t]' ) {
  debug_print('"3 digits" found on port ', port, ' in response to GET\n' );
  service_register( port:port, proto:"three_digits" );
  exit( 0 );
}

if( r =~ "^RFB [0-9]" ) {
  service_report( port:port, svc:"vnc" );
  replace_kb_item( name:"vnc/banner/" + port , value:r );
  exit( 0 );
}

if( match( string:r, pattern:"Language received from client:*Setlocale:*" ) ) {
  service_report( port:port, svc:"websm" );
  exit( 0 );
}

# invalid command (code=12064, len=1414541105)
# nb: Don't use a ^ anchor, the banner is located within some binary blob.
# nb: see sw_sphinxsearch_detect.nasl as well
if( banner = egrep( string:rbinstr_space, pattern:"invalid command \(code=([0-9]+), len=([0-9]+)\)" ) ) {
  service_register( port:port, proto:"sphinxapi", message:"A Sphinx search server seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server seems to be running on this port" );
  set_kb_item( name:"sphinxsearch/" + port + "/sphinxapi/banner", value:banner );
  exit( 0 );
}

# Examples:
# 2.0.9-id64-release (rel20-r4115)
# 2.1.2-id64-release (r4245)
# 2.0.4-release (r3135)
# 2.2.11-id64-release (95ae9a6)
# 2.8.0 4006794b@190128 release
# 3.0.2 e3d296ef@190531 release
#
# Binary:
# 0x00:  4B 00 00 00 0A 32 2E 38 2E 30 20 34 30 30 36 37    K....2.8.0 40067
# 0x10:  39 34 62 40 31 39 30 31 32 38 20 72 65 6C 65 61    94b@190128 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 00 00 00 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00       ...............
#
# 0x00:  61 00 00 00 0A 33 2E 30 2E 32 20 65 33 64 32 39    a....3.0.2 e3d29
# 0x10:  36 65 66 40 31 39 30 35 33 31 20 72 65 6C 65 61    6ef@190531 relea
# 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
# 0x30:  08 82 21 02 00 08 00 15 00 00 00 00 00 00 00 00    ..!.............
# 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 6D    ...............m
# 0x50:  79 73 71 6C 5F 6E 61 74 69 76 65 5F 70 61 73 73    ysql_native_pass
# 0x60:  77 6F 72 64 00
#
# 0x00:  48 00 00 00 0A 32 2E 30 2E 38 2D 69 64 36 34 2D    H....2.0.8-id64-
# 0x10:  72 65 6C 65 61 73 65 20 28 72 33 38 33 31 29 00    release (r3831).
# 0x20:  01 00 00 00 01 02 03 04 05 06 07 08 00 08 82 21    ...............!
# 0x30:  02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01    ................
# 0x40:  02 03 04 05 06 07 08 09 0A 0B 0C 0D                ............
#
# nb: see sw_sphinxsearch_detect.nasl as well
if( r_len > 10 && r[1] == '\0' && r[2] == '\0' && r[3] == '\0' &&
    eregmatch( string:rbinstr_space, pattern:"^.\s{4}[0-9.]+(-(id[0-9]+-)?release \([0-9a-z-]+\)| [0-9a-z]+@[0-9a-z]+ release)" ) ) {
  service_register( port:port, proto:"sphinxql", message:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  set_kb_item( name:"sphinxsearch/" + port + "/sphinxql/banner", value:rbinstr_space );
  exit( 0 );
}

if( match( string:r, pattern:"*<stream:stream*xmlns:stream='http://etherx.jabber.org/streams'*" ) ) {
  if( "jabber:server" >< r ) {
    service_register( port:port, proto:"xmpp-server", message:"A XMPP server-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP server-to-server service seems to be running on this port" );
    exit( 0 );
  } else if( "jabber:client" >< r ) {
    service_register( port:port, proto:"xmpp-client", message:"A XMPP client-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP client-to-server service seems to be running on this port" );
    exit( 0 );
  } else {
    log_message( port:port, data:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    service_register( port:port, proto:"xmpp-server", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    service_register( port:port, proto:"xmpp-client", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    exit( 0 );
  }
}

if( "Active Internet connections" >< r || "Active connections" >< r ) {
  service_register( port:port, proto:"netstat", message:"A netstat service seems to be running on this port." );
  log_message( port:port, data:"A netstat service seems to be running on this port." );
  exit( 0 );
}

if( "obby_welcome" >< r ) {
  service_register( port:port, proto:"obby", message:"A obby service seems to be running on this port." );
  log_message( port:port, data:"A obby service seems to be running on this port." );
  exit( 0 );
}

if( match( string:r, pattern:"*OK Cyrus IMSP version*ready*" ) ) {
  service_register( port:port, proto:"imsp", message:"A Cyrus IMSP service seems to be running on this port." );
  log_message( port:port, data:"A Cyrus IMSP service seems to be running on this port." );
  exit( 0 );
}

# e.g.  RESPONSE/None/53/application/json: {"status": 554, "message": "Unparsable message body"}
if( match( string:r, pattern:'RESPONSE/None/*/application/json:*{"status": *, "message": "*"}' ) ) {
  service_register( port:port, proto:"umcs", message:"A Univention Management Console Server service seems to be running on this port." );
  log_message( port:port, data:"A Univention Management Console Server service seems to be running on this port." );
  exit( 0 );
}

if( "DRb::DRbConnError" >< rbinstr_nospace ) {
  service_register( port:port, proto:"drb", message:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  log_message( port:port, data:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  exit( 0 );
}

# 9290 for raw scanning to peripherals with IEEE 1284.4 specifications. On three port HP JetDirects, the scan ports are 9290, 9291, and 9292.
# (When you connect to a raw scan port, the scan gateway sends back "00" if the connection to the peripheral's scan service was successful, "01"
# if somebody else is using it, and "02" if some other error, for example, the supported peripheral is not connected. Ports 9220, 9221, and 9222
# are the generic scan gateway ports currently only usable on 1284.4 peripherals.)
# Source: http://www2.cruzio.com/~jeffl/sco/lp/printservers.htm
if( port =~ "^929[0-2]$" && r =~ "^0[0-2]$") {
  service_register( port:port, proto:"iee-rsgw", message:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  log_message( port:port, data:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  exit( 0 );
}

if( port == 515 && rhexstr =~ "^ff$") {
  service_register( port:port, proto:"printer", message:"A LPD service seems to be running on this port." );
  log_message( port:port, data:"A LPD service seems to be running on this port." );
  exit( 0 );
}

# Running on a Hama IR110 WiFi Radio on port 514/tcp
# (Thread0): [      2.185608] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [      2.185860] I2S    (2): Timer fired at 0x00215C2E
# (Thread0): [      2.186123] SPDIF  (2): Timer fired at 0x00215E40
# (Thread2): [     16.463611] NET    (2): Notify Eth Link i/f 1 UP
# (Thread2): [     21.894697] NET    (2): Notify IP i/f 1 (192.168.0.1) UP
# (Thread2): [     22.072539] HTTP   (2): Found existing handle 1 (hama.wifiradiofrontier.com:80)
# (Thread2): [     22.158205] CB     (2): Received interface callback data ok.
# (Thread2): [     23.451059] UI     (2): IntSetupWizard connected
# (Thread0): [     25.139968] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [     25.140278] I2S    (2): Timer fired at 0x017F9D9A
# (Thread0): [     25.140583] SPDIF  (2): Timer fired at 0x017FA01F
# (Thread2): [     49.340946] RSA    (2): fsRsaGenerateKeyTask: Key created. Time taken 49299ms
#
# or
#
# (Thread0): [  11828.608232] I2S    (2): After waiting approx. 0.0 seconds...
# (Thread0): [  11828.608552] I2S    (2): Timer fired at 0xC10A3F89
# (Thread0): [  11828.608895] SPDIF  (2): Timer fired at 0xC10A4232

if( "(Thread" >< r && ( "Notify Wlan Link " >< r ||
    "Notify Eth Link " >< r ||
    "Received unknown command on socket" >< r ||
    "fsfsFlashFileHandleOpen" >< r ||
    "Found existing handle " >< r ||
    "After waiting approx. " >< r ||
    "Timer fired at " >< r ||
    "ControlSocketServerInstructClientToLeave" >< r ||
    ( "WFSAPI" >< r && "File not found" >< r ) ) ) {
  service_register( port:port, proto:"wifiradio-setup", message:"A WiFi radio setup service seems to be running on this port." );
  log_message( port:port, data:"A WiFi radio setup service seems to be running on this port." );
  exit( 0 );
}

# Sophos Remote Messaging / Management Server
if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r ) {
  service_register( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  exit( 0 );
}

if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  replace_kb_item( name:"check_mk_agent/banner/" + port, value:r );
  service_register( port:port, proto:"check_mk_agent", message:"A Check_MK Agent seems to be running on this port." );
  log_message( port:port, data:"A Check_MK Agent seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^\.NET" && ( "customErrors" >< r || "RemotingException" >< r ) ) {
  service_register( port:port, proto:"remoting", message:"A .NET remoting service seems to be running on this port." );
  log_message( port:port, data:"A .NET remoting service seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^-ERR wrong number of arguments for 'get' command" || egrep( string:r, pattern:"^-ERR unknown command 'Host:'" ) ||
    r =~ "^-DENIED Redis is running in protected mode" ) {
  service_register( port:port, proto:"redis", message:"A Redis server seems to be running on this port." );
  log_message( port:port, data:"A Redis server seems to be running on this port." );
  exit( 0 );
}

# 0x00:  41 4D 51 50 03 01 00 00 41 4D 51 50 00 01 00 00    AMQP....AMQP....
# 0x10:  00 00 00 19 02 00 00 00 00 53 10 C0 0C 04 A1 00    .........S......
# 0x20:  40 70 FF FF FF FF 60 7F FF 00 00 00 60 02 00 00    @p....`.....`...
# 0x30:  00 00 53 18 C0 53 01 00 53 1D C0 4D 02 A3 11 61    ..S..S..S..M...a
# 0x40:  6D 71 70 3A 64 65 63 6F 64 65 2D 65 72 72 6F 72    mqp:decode-error
# 0x50:  A1 37 43 6F 6E 6E 65 63 74 69 6F 6E 20 66 72 6F    .7Connection fro
# 0x60:  6D 20 63 6C 69 65 6E 74 20 75 73 69 6E 67 20 75    m client using u
# 0x70:  6E 73 75 70 70 6F 72 74 65 64 20 41 4D 51 50 20    nsupported AMQP
# 0x80:  61 74 74 65 6D 70 74 65 64                         attempted

if( "Connection from client using unsupported AMQP attempted" >< r || "amqp:decode-error" >< r ) {
  service_register( port:port, proto:"amqp", message:"A AMQP service seems to be running on this port." );
  log_message( port:port, data:"An AMQP service seems to be running on this port." );
  exit( 0 );
}

# 0x0000:  00 00 01 87 01 41 63 74 69 76 65 4D 51 00 00 00    .....ActiveMQ...
# 0x0010:  0C 01 00 00 01 75 00 00 00 0C 00 11 54 63 70 4E    .....u......TcpN
# 0x0020:  6F 44 65 6C 61 79 45 6E 61 62 6C 65 64 01 01 00    oDelayEnabled...
# 0x0030:  12 53 69 7A 65 50 72 65 66 69 78 44 69 73 61 62    .SizePrefixDisab
# 0x0040:  6C 65 64 01 00 00 09 43 61 63 68 65 53 69 7A 65    led....CacheSize
# 0x0050:  05 00 00 04 00 00 0C 50 72 6F 76 69 64 65 72 4E    .......ProviderN
# 0x0060:  61 6D 65 09 00 08 41 63 74 69 76 65 4D 51 00 11    ame...ActiveMQ..
# 0x0070:  53 74 61 63 6B 54 72 61 63 65 45 6E 61 62 6C 65    StackTraceEnable
# 0x0080:  64 01 01 00 0F 50 6C 61 74 66 6F 72 6D 44 65 74    d....PlatformDet
# 0x0090:  61 69 6C 73 09 00 50 4A 56 4D 3A 20 31 2E 38 2E    ails..PJVM: 1.8.
# 0x00A0:  30 5F 31 34 31 2C 20 32 35 2E 31 34 31 2D 62 31    0_141, 25.141-b1
# 0x00B0:  35 2C 20 4F 72 61 63 6C 65 20 43 6F 72 70 6F 72    5, Oracle Corpor
# 0x00C0:  61 74 69 6F 6E 2C 20 4F 53 3A 20 4C 69 6E 75 78    ation, OS: Linux
# 0x00D0:  2C 20 34 2E 31 33 2E 30 2D 31 2D 61 6D 64 36 34    , 4.13.0-1-amd64
# 0x00E0:  2C 20 61 6D 64 36 34 00 0C 43 61 63 68 65 45 6E    , amd64..CacheEn
# 0x00F0:  61 62 6C 65 64 01 01 00 14 54 69 67 68 74 45 6E    abled....TightEn
# 0x0100:  63 6F 64 69 6E 67 45 6E 61 62 6C 65 64 01 01 00    codingEnabled...
# 0x0110:  0C 4D 61 78 46 72 61 6D 65 53 69 7A 65 06 00 00    .MaxFrameSize...
# 0x0120:  00 00 06 40 00 00 00 15 4D 61 78 49 6E 61 63 74    ...@....MaxInact
# 0x0130:  69 76 69 74 79 44 75 72 61 74 69 6F 6E 06 00 00    ivityDuration...
# 0x0140:  00 00 00 00 75 30 00 20 4D 61 78 49 6E 61 63 74    ....u0. MaxInact
# 0x0150:  69 76 69 74 79 44 75 72 61 74 69 6F 6E 49 6E 69    ivityDurationIni
# 0x0160:  74 61 6C 44 65 6C 61 79 06 00 00 00 00 00 00 27    talDelay.......'
# 0x0170:  10 00 0F 50 72 6F 76 69 64 65 72 56 65 72 73 69    ...ProviderVersi
# 0x0180:  6F 6E 09 00 06 35 2E 31 34 2E 35                   on...5.14.5

if( "ActiveMQ" >< r && ( "PlatformDetails" >< r || "StackTraceEnable" >< r || "ProviderVersion" >< r || "TcpNoDelayEnabled" >< r ) ) {
  # nb: Set the response for later use in gsf/gb_apache_activemq_jms_detect.nasl
  set_kb_item( name:"ActiveMQ/JMS/banner/" + port, value:rbinstr_nospace );
  service_register( port:port, proto:"activemq_jms", message:"A ActiveMQ JMS service seems to be running on this port." );
  log_message( port:port, data:"A ActiveMQ JMS service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  00 3A 2D 45 52 52 20 45 72 72 6F 72 20 72 65 61    .:-ERR Error rea
# 0x10:  64 69 6E 67 20 66 72 6F 6D 20 73 6F 63 6B 65 74    ding from socket
# 0x20:  3A 20 55 6E 6B 6E 6F 77 6E 20 70 72 6F 74 6F 63    : Unknown protoc
# 0x30:  6F 6C 20 65 78 63 65 70 74 69 6F 6E 00 00          ol exception..
#
# Weblogic 12.3 NodeManager
# nb: Using only the default port 5556 as the pattern looks too generic
# and might match against other Java based products.
if( port == 5556 && ":-ERR Error reading from socket: Unknown protocol exception" >< r ) {
  service_register( port:port, proto:"nodemanager", message:"A Weblogic NodeManager service seems to be running on this port." );
  log_message( port:port, data:"A Weblogic NodeManager service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  04 20 4E 73 75 72 65 20 41 75 64 69 74 20 4C 69    . Nsure Audit Li
# 0x10:  6E 75 78 20 5B 37 66 35 31 32 32 30 32 3A 31 5D    nux [7f512202:1]
# 0x20:  0D 0A                                           ..
# Running on 1289/tcp
if( r =~ "Nsure Audit .* \[.*\]" ) {
  service_register( port:port, proto:"naudit", message:"A Novell Audit Secure Logging Server service seems to be running on this port." );
  log_message( port:port, data:"A Novell Audit Secure Logging Server service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  45 52 52 4F 52 0D 0A 45 52 52 4F 52 0D 0A 45 52    ERROR..ERROR..ER
# 0x10:  52 4F 52 0D 0A                                     ROR..
if( r =~ '^ERROR\r\nERROR\r\nERROR\r\n$' ) {
  service_register( port:port, proto:"memcached", message:"A Memcached service seems to be running on this port." );
  log_message( port:port, data:"A Memcached service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  55 6E 6B 6E 6F 77 6E 20 6D 65 73 73 61 67 65       Unknown message
# https://www.eyelock.com/index.php/products/myris
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-March/001372.html
# nb: Only checking the two ports mentioned in the mailing list post above as
# the message is quite too common to check on all ports
if( ( port == 8083 || port == 9099 ) && rhexstr == "556e6b6e6f776e206d657373616765" ) {
  service_register( port:port, proto:"myris", message:"A Myris service seems to be running on this port." );
  log_message( port:port, data:"A Myris service seems to be running on this port." );
  exit( 0 );
}

# nb: Keep in sync with find_service2.nasl.
# Daytime seems to be responding late or even not to the HELP
# request there so trying to detect it here.
if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[e�]c|F[e�]v|Avr|Mai|Ao[u�]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$",
          string:r ) ||
    ereg( pattern:"^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[e�]c|F[e�]v|Avr|Mai|Ao[u�]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string:r, icase:TRUE ) ||
    r =~ '^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$' ||
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$' ||
    ereg( pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r ) ||
    # MS flavor of daytime
    ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r ) ||
    # e.g. 0:00:42 07.02.2018 or 14:07:03 16.01.2018
    r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[0-2])\\.(19|20)[0-9][0-9][ \t\r\n]*$' ) {
  service_register( port:port, proto:"daytime" );
  log_message( port:port, data:"Daytime is running on this port" );
  exit( 0 );
}

# On 623/tcp
# 0x00:  00 00 00 02 09 00 00 00 01 00 00 00 00 00 00 00    ................
# 0x10:  00                                                 .
if( rhexstr =~ "^0000000209000000010000000000000000$" ) {
  service_register( port:port, proto:"ipmi-rmcp", message:"A IPMI RMCP service seems to be running on this port." );
  log_message( port:port, data:"A IMPI RMCP service seems to be running on this port." );
  exit( 0 );
}

# On 2701/tcp
# SCCM Remote Control (control), https://docs.microsoft.com/en-us/sccm/core/plan-design/hierarchy/ports
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-April/001378.html
# 0x00:  22 00 00 80 20 00 53 00 54 00 41 00 52 00 54 00    "... .S.T.A.R.T.
# 0x10:  5F 00 48 00 41 00 4E 00 44 00 53 00 48 00 41 00    _.H.A.N.D.S.H.A.
# 0x20:  4B 00 45 00 00 00                                  K.E...
if( rhexstr =~ "^220000802000530054004100520054005F00480041004E0044005300480041004B0045000000" ) {
  service_register( port:port, proto:"sccm-control", message:"A SCCM Remote Control (control) service seems to be running on this port." );
  log_message( port:port, data:"A SCCM Remote Control (control) service seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^root@metasploitable:/# " ) {
  service_register( port:port, proto:"rootshell", message:"A root shell of Metasploitable seems to be running on this port." );
  log_message( port:port, data:"A root shell of Metasploitable seems to be running on this port." );
  exit( 0 );
}

# pfstatd on 9999/tcp
# 0x0000:  2D 31 20 2D 20 30 20 30 0A 30 20 2D 20 30 20 30    -1 - 0 0.0 - 0 0
# 0x0010:  0A 30 20 2D 20 31 20 30 0A 30 20 2D 20 32 20 30    .0 - 1 0.0 - 2 0
# 0x0020:  0A 30 20 2D 20 33 20 30 0A 30 20 2D 20 34 20 30    .0 - 3 0.0 - 4 0
# 0x0030:  0A 30 20 2D 20 35 20 30 0A 30 20 2D 20 36 20 30    .0 - 5 0.0 - 6 0
# 0x0040:  0A 30 20 2D 20 37 20 30 0A 30 20 2D 20 38 20 30    .0 - 7 0.0 - 8 0
# 0x0050:  0A 30 20 2D 20 39 20 30 0A 30 20 2D 20 31 30 20    .0 - 9 0.0 - 10
# 0x0060:  30 0A 30 20 2D 20 31 31 20 30 0A 30 20 2D 20 31    0.0 - 11 0.0 - 1
# 0x0070:  32 20 30 0A 30 20 2D 20 31 33 20 30 0A 30 20 2D    2 0.0 - 13 0.0 -
# 0x0080:  20 31 34 20 30 0A 30 20 2D 20 31 35 20 30 0A 30     14 0.0 - 15 0.0
# 0x0090:  20 2D 20 31 36 20 30 0A 30 20 2D 20 31 37 20 30     - 16 0.0 - 17 0
# 0x00A0:  0A 30 20 2D 20 31 38 20 30 0A 30 20 2D 20 31 39    .0 - 18 0.0 - 19
# 0x00B0:  20 30 0A 30 20 2D 20 32 30 20 30 0A 31 20 61 6C     0.0 - 20 0.1 al
# 0x00C0:  6C 20 30 20 30 0A 31 20 61 6C 6C 20 31 20 30 0A    l 0 0.1 all 1 0.
if( egrep( string:r, pattern:"^[0-9]+ (all|carp|em0|enc|enc0|lo|lo0|pflog0|pflog|\-) [0-9]+ [0-9]+$" ) ) {
  service_register( port:port, proto:"pfstatd", message:"A pfstatd service seems to be running on this port." );
  log_message( port:port, data:"A pfstatd service seems to be running on this port." );
  exit( 0 );
}

# R1Soft backup system on, http://wiki.r1soft.com/display/ServerBackup/Configure+network+ports
#
# Reported via http://lists.wald.intevation.org/pipermail/openvas-plugins/2018-May/001393.html
# 1167/tcp:
# 0x0000:  00 00 01 2E 52 AB 02 0A 14 08 A3 80 04 10 01 18    ....R...........
# 0x0010:  00 20 00 2A 08 4E 4F 54 46 4F 55 4E 44 10 00 1A    . .*.NOTFOUND...
# 0x0020:  90 02 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 55 42    ..-----BEGIN PUB
# 0x0030:  4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D 0A 4D 49 47    LIC KEY-----.MIG
# 0x0040:  66 4D 41 30 47 43 53 71 47 53 49 62 33 44 51 45    fMA0GCSqGSIb3DQE
# 0x0050:  42 41 51 55 41 41 34 47 4E 41 44 43 42 69 51 4B    BAQUAA4GNADCBiQK
# 0x0060:  42 67 51 44 32 78 57 72 31 58 64 5A 36 45 69 76    BgQD2xWr1XdZ6Eiv
#
# Alternatives found on the net on port 8000/tcp:
#
# 0x0000:  00 00 01 2E 52 AB 02 0A 14 08 A3 80 04 10 02 18    ....R...........
# 0x0010:  00 20 00 2A 08 4E 4F 54 46 4F 55 4E 44 10 00 1A    . .*.NOTFOUND...
# 0x0020:  90 02 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 55 42    ..-----BEGIN PUB
# 0x0030:  4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D 0A 4D 49 47    LIC KEY-----.MIG
# 0x0040:  66 4D 41 30 47 43 53 71 47 53 49 62 33 44 51 45    fMA0GCSqGSIb3DQE
# 0x0050:  42 41 51 55 41 41 34 47 4E 41 44 43 42 69 51 4B    BAQUAA4GNADCBiQK
# 0x0060:  42 67 51 44 48 4D 54 4E 6E 51 31 44 2F 78 74 79    BgQDHMTNnQ1D/xty
#
# or 8001/tcp:
# 0x0000:  00 00 01 32 52 AF 02 0A 18 08 A3 80 04 10 02 18    ...2R...........
# 0x0010:  00 20 01 2A 0C 56 4D 77 61 72 65 56 4D 77 61 72    . .*.VMwareVMwar
# 0x0020:  65 10 00 1A 90 02 2D 2D 2D 2D 2D 42 45 47 49 4E    e.....-----BEGIN
# 0x0030:  20 50 55 42 4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D     PUBLIC KEY-----
# 0x0040:  0A 4D 49 47 66 4D 41 30 47 43 53 71 47 53 49 62    .MIGfMA0GCSqGSIb
# 0x0050:  33 44 51 45 42 41 51 55 41 41 34 47 4E 41 44 43    3DQEBAQUAA4GNADC
# 0x0060:  42 69 51 4B 42 67 51 43 70 7A 73 39 54 47 6A 66    BiQKBgQCpzs9TGjf
#
# or 88/tcp which are sharing parts with the original reported service.
#
# 0x0000:  00 00 01 32 52 AF 02 0A 18 08 A3 80 04 10 01 18    ...2R...........
# 0x0010:  00 20 01 2A 0C 56 4D 77 61 72 65 56 4D 77 61 72    . .*.VMwareVMwar
# 0x0020:  65 10 00 1A 90 02 2D 2D 2D 2D 2D 42 45 47 49 4E    e.....-----BEGIN
# 0x0030:  20 50 55 42 4C 49 43 20 4B 45 59 2D 2D 2D 2D 2D     PUBLIC KEY-----
# 0x0040:  0A 4D 49 47 66 4D 41 30 47 43 53 71 47 53 49 62    .MIGfMA0GCSqGSIb
# 0x0050:  33 44 51 45 42 41 51 55 41 41 34 47 4E 41 44 43    3DQEBAQUAA4GNADC
# 0x0060:  42 69 51 4B 42 67 51 44 66 4D 68 41 36 75 50 63    BiQKBgQDfMhA6uPc
if( rhexstr =~ "^000001..52..020A..08A3800410..180020..2A.*10001A9002" && "-----BEGIN PUBLIC KEY-----" >< r && "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" >< r ) {
  service_register( port:port, proto:"r1soft_backupagent", message:"A R1Soft Backup Agent seems to be running on this port." );
  log_message( port:port, data:"A R1Soft Backup Agent seems to be running on this port." );
  exit( 0 );
}

# https://www.iana.org/assignments/beep-parameters/beep-parameters.xhtml
# 0x00:  52 50 59 20 30 20 30 20 2E 20 30 20 31 30 32 0D    RPY 0 0 . 0 102.
# 0x10:  0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61    .Content-Type: a
# 0x20:  70 70 6C 69 63 61 74 69 6F 6E 2F 62 65 65 70 2B    pplication/beep+
# 0x30:  78 6D 6C 0D 0A 0D 0A 3C 67 72 65 65 74 69 6E 67    xml....<greeting
# 0x40:  3E 3C 70 72 6F 66 69 6C 65 20 75 72 69 3D 22 68    ><profile uri="h
# 0x50:  74 74 70 3A 2F 2F 69 61 6E 61 2E 6F 72 67 2F 62    ttp://iana.org/b
# 0x60:  65 65 70 2F 54 4C 53 22 2F 3E 3C 2F 67 72 65 65    eep/TLS"/></gree
# 0x70:  74 69 6E 67 3E 0D 0A 45 4E 44 0D 0A                ting>..END..
#
# nb: beep/xmlrpc has application/xml as the Content-Type so using some
# different patterns here.
# nb: Have seen a response to http_get and spontaneuos for this so the same check is
# done in find_service_spontaneous.nasl as well. Please keep both in sync.
if( ( r =~ "^RPY [0-9] [0-9]" && "Content-Type: application/" >< r ) ||
    ( "<profile uri=" >< r && "http://iana.org/beep/" >< r ) ||
    "Content-Type: application/beep" >< r ) {
  service_register( port:port, proto:"beep", message:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
  exit( 0 );
}

# https://github.com/beanshell/beanshell/blob/master/src/main/resources/bsh/commands/server.bsh
# 0x00:  42 65 61 6E 53 68 65 6C 6C 20 32 2E 30 62 34 20    BeanShell 2.0b4
# 0x10:  2D 20 62 79 20 50 61 74 20 4E 69 65 6D 65 79 65    - by Pat Niemeye
# 0x20:  72 20 28 70 61 74 40 70 61 74 2E 6E 65 74 29 0A    r (pat@pat.net).
# 0x30:  62 73 68 20 25 20 2F 2F 20 45 72 72 6F 72 3A 20    bsh % // Error:
# 0x40:  50 61 72 73 65 72 20 45 72 72 6F 72 3A 20 49 6E    Parser Error: In
# 0x50:  20 66 69 6C 65 3A 20 3C 75 6E 6B 6E 6F 77 6E 3E     file: <unknown>
# 0x60:  20 45 6E 63 6F 75 6E 74 65 72 65 64 20 22 48 6F     Encountered "Ho
# 0x70:  73 74 22 20 61 74 20 6C 69 6E 65 20 32 2C 20 63    st" at line 2, c
# 0x80:  6F 6C 75 6D 6E 20 31 2E 0A 0A 62 73 68 20 25 20    olumn 1...bsh %
#
# nb: With and without the banner. Just to be sure...
if( r =~ "^bsh % " || r =~ "^BeanShell " || "- by Pat Niemeyer (pat@pat.net)" >< r ) {
  service_register( port:port, proto:"beanshell", message:"A BeanShell listener service seems to be running on this port." );
  log_message( port:port, data:"A BeanShell listener service seems to be running on this port." );
  set_kb_item( name:"beanshell_listener/detected", value:TRUE ); # nb: No default port. Key is used as mandatory_key().
  exit( 0 );
}

# Running on a Hama IR110 WiFi Radio on port 10003/tcp
# Response length is always 261 or 263 bytes...
# 0x0000:  77 30 32 35 36 41 8F F6 EE 52 63 48 15 DB 14 B1    w0256A...RcH....
# 0x0010:  92 B6 5D 67 58 D1 76 C4 0F 45 D8 82 73 81 A2 2F    ..]gX.v..E..s../
# 0x0020:  F7 FD 49 F7 1B FB 94 93 56 C4 A6 9D 4D D7 67 FF    ..I.....V...M.g.
# 0x0030:  16 69 40 39 97 3C 51 D7 91 BD 47 F2 08 C2 D3 0D    .i@9.<Q...G.....
# 0x0040:  25 3C 7C 5C 9A 9D 4C C0 3E 7A 4A D6 D8 52 B4 57    %<|\..L.>zJ..R.W
# 0x0050:  CF 48 DE 49 9A 58 6F BC 02 B5 E3 D3 AF 75 47 DA    .H.I.Xo......uG.
# 0x0060:  83 BF 64 A4 D4 8E 24 00 BD C6 86 6C 69 AE DA B4    ..d...$....li...
# 0x0070:  BE C7 00 A0 24 58 0D F1 04 59 22 3C 4C EF C6 51    ....$X...Y"<L..Q
# 0x0080:  0B 8B 1A 09 B6 DC 3F 2C 1C A8 5C A7 07 CD C3 05    ......?,..\.....
# 0x0090:  00 6B E1 59 4A 1F 53 04 74 26 BD 03 EB 8E 74 9F    .k.YJ.S.t&....t.
# 0x00A0:  8E 48 EF F7 95 B0 B6 28 A9 5E 10 EB 47 88 02 97    .H.....(.^..G...
# 0x00B0:  B3 20 11 65 B0 01 9F 14 7B 33 03 58 E3 D4 B1 C2    . .e....{3.X....
# 0x00C0:  25 41 7D 9A 6E B7 F2 98 78 90 51 FE 5C 32 42 EC    %A}.n...x.Q.\2B.
# 0x00D0:  8E FD AD 93 E7 51 9D 82 19 79 12 76 EA 91 B4 4F    .....Q...y.v...O
# 0x00E0:  48 52 1B BB E3 F8 C3 B9 3A 37 6C BB E0 3A 32 49    HR......:7l..:2I
# 0x00F0:  88 D9 25 79 D4 AB 05 72 C8 79 1A 6C 21 40 BF 7C    ..%y...r.y.l!@.|
# 0x0100:  11 68 2E DD 1C                                     .h...
#
# nb: Pattern is not that reliable so checking the length as well...
if( r =~ "^w0256" && ( r_len == 261 || r_len == 263 ) ) {
  service_register( port:port, proto:"wifiradio-unknown", message:"An unknown service related to a WiFi radio seems to be running on this port." );
  log_message( port:port, data:"An unknown service related to a WiFi radio seems to be running on this port." );
  exit( 0 );
}

# Unknown telnet service running on 23/tcp. The check is not that reliable so checking the port as well...
# 0x00:  43 6F 6E 6E 65 63 74 69 6F 6E 20 72 65 66 75 73    Connection refus
# 0x10:  65 64 0D 0A                                        ed..
if( port == 23 && rhexstr == "436f6e6e656374696f6e20726566757365640d0a" ) {
  service_register( port:port, proto:"telnet", message:"A telnet service rejecting the access of the scanner seems to be running on this port." );
  log_message( port:port, data:"A telnet service rejecting the access of the scanner seems to be running on this port." );
  exit( 0 );
}

# Found on the IceWarp Suite (but there might be more similar products). This is a SIP service
# which isn't responding to our SIP OPTIONS request of sip_detection_tcp.nasl and find_service5.nasl
# 0x00:  53 49 50 2F 32 2E 30 20 34 30 30 20 42 61 64 20    SIP/2.0 400 Bad
# 0x10:  52 65 71 75 65 73 74 0D 0A 55 73 65 72 2D 41 67    Request..User-Ag
# 0x20:  65 6E 74 3A 20 49 63 65 57 61 72 70 20 53 49 50    ent: IceWarp SIP
# 0x30:  20 31 31 2E 31 2E 32 2E 31 20 44 45 42 37 20 78     11.1.2.1 DEB7 x
# 0x40:  36 34 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67    64..Content-Leng
# 0x50:  74 68 3A 20 30 0D 0A 56 69 61 3A 20 3B 72 65 63    th: 0..Via: ;rec
# 0x60:  65 69 76 65 64 3D 31 39 32 2E 31 36 38 2E 31 2E    eived=192.168.1.
# 0x70:  31 30 3B 72 70 6F 72 74 3D 34 35 34 36 31 3B 74    10;rport=45461;t
# 0x80:  72 61 6E 73 70 6F 72 74 3D 54 43 50 0D 0A 48 6F    ransport=TCP..Ho
# 0x90:  73 74 3A 20 74 65 73 74 0D 0A 0D 0A                st: test....
#
# Another special case on e.g. a AVM FRITZ!Box
# 0x0000:  53 49 50 2F 32 2E 30 20 34 30 30 20 49 6C 6C 65    SIP/2.0 400 Ille
# 0x0010:  67 61 6C 20 72 65 71 75 65 73 74 20 6C 69 6E 65    gal request line
# 0x0020:  0D 0A 46 72 6F 6D 3A 20 3C 73 69 70 3A 6D 69 73    ..From: <sip:mis
# 0x0030:  73 69 6E 67 3E 0D 0A 54 6F 3A 20 3C 73 69 70 3A    sing>..To: <sip:
# 0x0040:  6D 69 73 73 69 6E 67 3E 3B 74 61 67 3D 62 61 64    missing>;tag=bad
# 0x0050:  72 65 71 75 65 73 74 0D 0A 55 73 65 72 2D 41 67    request..User-Ag
# 0x0060:  65 6E 74 3A 20 46 52 49 54 5A 21 4F 53 0D 0A 43    ent: FRITZ!OS..C
# 0x0070:  6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 30    ontent-Length: 0
# 0x0080:  0D 0A 0D 0A 53 49 50 2F 32 2E 30 20 34 30 30 20    ....
if( sip_verify_banner( data:r ) ) {
  service_register( port:port, proto:"sip", message:"A service supporting the SIP protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the SIP protocol seems to be running on this port." );
  exit( 0 );
}

# Citrix NetScaler Metric Exchange Protocol on 3011/tcp
# 0x00:  10 00 00 00 A5 A5 00 00 D4 00 60 01 00 00 00 00    ..........`.....
if( rhexstr == "10000000a5a50000d400600100000000" ) {
  service_register( port:port, proto:"mep", message:"A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
  exit( 0 );
}

# chargen service, this has a longer string (the following is only an excerpt) like e.g.:
#
# 0x0000:  20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F     !"#$%&'()*+,-./
# 0x0010:  30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F    0123456789:;<=>?
# 0x0020:  40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F    @ABCDEFGHIJKLMNO
# 0x0030:  50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F    PQRSTUVWXYZ[\]^_
# 0x0040:  60 61 62 63 64 65 66 67 0D 0A 21 22 23 24 25 26    `abcdefg..!"#$%&
# 0x0050:  27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36    '()*+,-./0123456
# 0x0060:  37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46    789:;<=>?@ABCDEF
# 0x0070:  47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56    GHIJKLMNOPQRSTUV
# 0x0080:  57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66    WXYZ[\]^_`abcdef
# 0x0090:  67 68 0D 0A 22 23 24 25 26 27 28 29 2A 2B 2C 2D    gh.."#$%&'()*+,-
# 0x00A0:  2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D    ./0123456789:;<=
#
# Ensuring that at least 3 patterns match
# In case a pattern is missing or doesn't make it into the response (due to it being slow), the service will still be reported
# nb: See also find_service2.nasl and gb_chargen_detect_tcp.nasl/gb_chargen_detect_udp.nasl
chargen_found = 0;
foreach chargen_pattern( make_list( '!"#$%&\'()*+,-./', "ABCDEFGHIJ", "abcdefg", "0123456789", ":;<=>?@", "KLMNOPQRSTUVWXYZ" ) ) {
  if( chargen_pattern >< r )
    chargen_found++;
}
if( chargen_found > 2 ) {
  replace_kb_item( name:"chargen/tcp/" + port + "/banner", value:chomp( r ) );
  service_register( port:port, proto:"chargen", message:"A chargen service seems to be running on this port." );
  log_message( port:port, data:"A chargen service seems to be running on this port." );
  exit( 0 );
}

# Xrdp on 3389/tcp seems to be responding like this
# 0x00:  03 00 00 09 02 F0 80 21 80                         .......!.
if( rhexstr == "0300000902f0802180" ) {
  service_register( port:port, proto:"ms-wbt-server", message:"A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
  log_message( port:port, data:"A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
  set_kb_item( name:"rdp/" + port + "/isxrdp", value:TRUE ); # Later used in check_xrdp() of ms_rdp_detect.nasl to avoid an already done request.
  exit( 0 );
}

# Service related to Siemens Building Management Systems (MBC, MEC, PXCM)
# on port 5441/tcp. The returned text seems to be deployment specific so
# we need to update this if we see other similar deployments. Make sure
# to not add any pattern with sensitive information in here...
if( port == 5441 &&
    ( "HEATINGNODE" >< r || "COOLINGNODE" >< r ||
      "CTL FLOW MAX" >< r || "OCC FLOW" >< r ||
      "$paneldefault" >< r || "NEGATIVE" >< r ||
      "POSITIVE" >< r ) ) {
  service_register( port:port, proto:"siemens-bms", message:"A service related to Siemens Building Management Systems seems to be running on this port." );
  log_message( port:port, data:"A service related to Siemens Building Management Systems seems to be running on this port." );
  exit( 0 );
}

# OMAPI https://en.wikipedia.org/wiki/OMAPI
# 0x00:  00 00 00 64 00 00 00 18                            ...d....
if( rhexstr == "0000006400000018" ) {
  service_register( port:port, proto:"omapi", message:"A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
  log_message( port:port, data:"A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
  exit( 0 );
}

# Comvault Complete Backup & Recovery v11 sp 9-12
# https://www.commvault.com/complete-backup
# 0x00:  00 00 10 03 09 00 01 03 09 00 00 00 00 00 FF E8    ................
# 0x10:  00 00 00 0C 00 01 00 04 00 00 00 02 00 00 00 00    ................
# 0x20:  00 00 00 02                                        ....
if( rhexstr == "0000100309000103090000000000ffe80000000c00010004000000020000000000000002" ) {
  service_register( port:port, proto:"comvault-complete-backup", message:"A Comvault Complete Backup & Recovery service seems to be running on this port." );
  log_message( port:port, data:"A Comvault Complete Backup & Recovery service seems to be running on this port." );
  exit( 0 );
}

# Digi AnywhereUSB/14
# https://www.digi.com/products/usb-and-serial-connectivity/usb-over-ip-hubs/anywhereusb
# 0x00:  FF 14 50 6F 72 74 20 69 73 20 6F 75 74 20 6F 66    ..Port is out of
# 0x10:  20 72 61 6E 67 65 00 FF 14 50 6F 72 74 20 69 73     range...Port is
# 0x20:  20 6F 75 74 20 6F 66 20 72 61 6E 67 65 00 FF 14     out of range...
# 0x30:  50 6F 72 74 20 69 73 20 6F 75 74 20 6F 66 20 72    Port is out of r
# 0x40:  61 6E 67 65 00 FF 14 50 6F 72 74 20 69 73 20 6F    ange...Port is o
# 0x50:  75 74 20 6F 66 20 72 61 6E 67 65 00 FF 14 50 6F    ut of range...Po
# 0x60:  72 74 20 69 73 20 6F 75 74 20 6F 66 20 72 61 6E    rt is out of ran
# 0x70:  67 65 00                                           ge.
if( rhexstr == "ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500" ) {
  service_register( port:port, proto:"digi-usb", message:"A Digi AnywhereUSB/14 service seems to be running on this port." );
  log_message( port:port, data:"A Digi AnywhereUSB/14 service seems to be running on this port." );
  exit( 0 );
}

# mariadb - galera cluster port on e.g. 4567/tcp
# 0x00:  24 00 00 02 43 9D 3A 7F 00 01 10 00 B3 B7 1E CD    $...C.:.........
# 0x10:  A6 E7 11 E8 B9 33 E6 E4 2B A3 C7 AF 29 9F 98 AD    .....3..+...)...
# 0x20:  A8 3B 11 E8 A6 2B 7F 47 06 68 BC B7                .;...+.G.h..
if( rhexstr == "24000002439d3a7f00011000b3b71ecda6e711e8b933e6e42ba3c7af299f98ada83b11e8a62b7f470668bcb7 " ) {
  service_register( port:port, proto:"digi-usb", message:"A MariaDB galera cluster service seems to be running on this port." );
  log_message( port:port, data:"A MariaDB galera cluster service seems to be running on this port." );
  exit( 0 );
}

# Various IRC servers, e.g.
# nb: $hostname/$ip are placeholders for the hostname/ip of the target system, * are no placeholders and received as such...
# :irc.$hostname NOTICE AUTH :*** Looking up your hostname...
# ERROR :Your host is trying to (re)connect too fast -- throttled.
# :unknown.host 451 GET :You have not registered
# :$hostname NOTICE IP_LOOKUP :*** Looking up your hostname...
# :irc.$hostname NOTICE * :*** Looking up your hostname...
# ERROR :Trying to reconnect too fast.
# ERROR :Closing Link: [$ip] (Throttled: Reconnecting too fast)
if( r =~ "^:.* NOTICE AUTH :\*\*\* Looking up your hostname" ||
    r =~ "^ERROR :Your host is trying to \(re\)connect too fast -- throttled\." ||
    r =~ "^:.* 451 GET :You have not registered" ||
    r =~ "^:.* NOTICE IP_LOOKUP :\*\*\* Looking up your hostname\.\.\." ||
    r =~ "^:.* NOTICE \* :\*\*\* Looking up your hostname\.\.\." ||
    r =~ "^ERROR :Trying to reconnect too fast." ||
    ( r =~ "^ERROR :Closing Link:" && "(Throttled: Reconnecting too fast)" >< r ) ) {
  service_register( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );
  log_message( port:port, data:"An IRC server seems to be running on this port." );
  exit( 0 );
}

# rsh on 514/tcp if there is something wrong with the name resolution on the target host.
# The "real" detection will happen in rsh.nasl as it won't response if working correctly...
# 0x00:  01 67 65 74 6E 61 6D 65 69 6E 66 6F 3A 20 54 65    .getnameinfo: Te
# 0x10:  6D 70 6F 72 61 72 79 20 66 61 69 6C 75 72 65 20    mporary failure # nb: Ending space...
# 0x20:  69 6E 20 6E 61 6D 65 20 72 65 73 6F 6C 75 74 69    in name resoluti
# 0x30:  6F 6E 0A                                           on.
if( port == 514 && "getnameinfo: Temporary failure in name resolution" >< r ) {
  service_register( port:port, proto:"rsh", message:"A rsh service seems to be running on this port." );
  log_message( port:port, data:"A rsh service seems to be running on this port." );
  exit( 0 );
}

# https://nmap.org/book/nping-man-echo-mode.html
# 0x00:  01 01 00 18 65 23 33 C8 5B FB 9A 3D 00 00 00 00    ....e#3.[..=....
# 0x10:  56 5A 7B BE DF CC B2 0D CF 2B 9E 79 ED D6 70 FE    VZ{......+.y..p.
# 0x20:  74 46 96 FF 72 3F 0B 68 F6 A1 D3 85 C1 BD 54 64    tF..r?.h......Td
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  17 F9 B0 49 07 8F 33 55 F3 19 4F 1E F4 4A F0 46    ...I..3U..O..J.F
# 0x50:  1E 5E 68 55 D5 A4 45 5E FA 18 D7 72 66 D8 AE EA    .^hU..E^...rf...
#
# or:
#
# 0x00:  01 01 00 18 5E EB 28 9B 5B FB 9A 24 00 00 00 00    ....^.(.[..$....
# 0x10:  E6 18 A4 F8 8B E3 55 A6 72 BE 37 A7 7E 83 5A 54    ......U.r.7.~.ZT
# 0x20:  48 A1 D1 77 5C FE 50 B6 45 AA 31 AB 08 FB CC 5D    H..w\.P.E.1....]
# 0x30:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# 0x40:  B3 8F 34 BD B6 A6 6A 6D 4F E5 2E 53 EB 0B DE AD    ..4...jmO..S....
# 0x50:  01 DF 28 BD F0 28 90 EF CE C2 08 3B 23 59 E6 61    ..(..(.....;#Y.a
if( rhexstr =~ "^01010018.{16}00000000.{64}0{32}.{64}$" ) {
  service_register( port:port, proto:"nping-echo", message:"An nping-echo server seems to be running on this port." );
  log_message( port:port, data:"An nping-echo server seems to be running on this port." );
  exit( 0 );
}

# 0x00:  39 39 46 46 31 42 03 01 39 39 39 39 46 46 31 42    99FF1B..9999FF1B
# 0x10:  03 01 39 39 39 39 46 46 31 42 03 01 39 39 39 39    ..9999FF1B..9999
# 0x20:  46 46 31 42 03 01 39 39 39 39 46 46 31 42 03 01    FF1B..9999FF1B..
# 0x30:  39 39 39 39 46 46 31 42 03 01 39 39 39 39 46 46    9999FF1B..9999FF
# 0x40:  31 42 03 01 39 39 39 39 46 46 31 42 03 01 39 39    1B..9999FF1B..99
# 0x50:  39 39 46 46 31 42 03 01 39 39 39 39 46 46 31 42    99FF1B..9999FF1B
# 0x60:  03
#
# or:
#
# 0x00:  01 39 39 39 39 46 46 31 42 03 01 39 39 39 39 46    .9999FF1B..9999F
# 0x10:  46 31 42 03 01 39 39 39 39 46 46 31 42 03 01 39    F1B..9999FF1B..9
# 0x20:  39 39 39 46 46 31 42 03 01 39 39 39 39 46 46 31    999FF1B..9999FF1
# 0x30:  42 03 01 39 39 39 39 46 46 31 42 03 01 39 39 39    B..9999FF1B..999
# 0x40:  39 46 46 31 42 03 01 39 39 39 39 46 46 31 42 03    9FF1B..9999FF1B.
# 0x50:  01 39 39 39 39 46 46 31 42 03 01 39 39 39 39 46    .9999FF1B..9999F
# 0x60:  46 31 42 03                                        F1B.
#
# nb: See find_service6.nasl as well
#
# nb: The last digit is the EXT char which defaults to 0x03 but can be changed on some devices according to the vendor documentation.
if( rhexstr =~ "013939393946463142.." ) {
  service_register( port:port, proto:"automated-tank-gauge", message:"A Automated Tank Gauge (ATG) service seems to be running on this port." );
  log_message( port:port, data:"A Automated Tank Gauge (ATG) service seems to be running on this port." );
  exit( 0 );
}

# on port 1050/tcp:
# 0x00:  46 69 6E 67 65 72 20 6F 6E 6C 69 6E 65 20 75 73    Finger online us
# 0x10:  65 72 20 6C 69 73 74 20 72 65 71 75 65 73 74 20    er list request # nb: space
# 0x20:  64 65 6E 69 65 64 2E 0D 0A 0A                      denied....
#
# on port 79/tcp:
# 0x00:  55 6E 61 62 6C 65 20 74 6F 20 66 69 6E 64 20 73    Unable to find s
# 0x10:  70 65 63 69 66 69 65 64 20 75 73 65 72 2E 0D 0A    pecified user...
#
# 0x00:  4C 6F 67 69 6E 20 6E 61 6D 65 3A 20 47 45 54 20    Login name: GET # nb: space
# 0x10:  20 20 20 20 20 20 09 09 09 49 6E 20 72 65 61 6C          ...In real
# 0x20:  20 6C 69 66 65 3A 20 3F 3F 3F 0D 0A                 life: ???..
#
# nb: This example below is shorter because private IP/hostnames were removed.
# 0x0000:  0D 0A 20 20 20 20 4C 69 6E 65 20 20 20 20 20 55    ..    Line     U
# 0x0010:  73 65 72 20 20 20 20 20 20 48 6F 73 74 28 73 29    ser      Host(s)
# 0x0020:  20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20                    # nb: spaces
# 0x0030:  20 20 49 64 6C 65 20 4C 6F 63 61 74 69 6F 6E 0D      Idle Location.
# 0x0040:  0A 20 20 33 32 20 76 74 79 20 30 20 20 20 20 20    .  32 vty 0     # nb: spaces
# 0x0050:  20 20 20 20 20 20 20 20 69 64 6C 65 20 20 20 20            idle    # nb: spaces
# 0x0060:  20 20 20 20 20 20 20 20 20 20 20 20 20 30 30 3A                 00:
# 0x0070:  30 30 3A 30 31 20 31 35 34 2E 31 31 37 2E 31 35    00:01
if( r == 'Finger online user list request denied.\r\n\n' ||
    r == 'Unable to find specified user.\r\n' ||
    egrep( string:r, pattern:"Line\s+User\s+Host", icase:TRUE ) ||
    egrep( string:r, pattern:"Login\s+Name\s+TTY", icase:TRUE ) ||
    eregmatch( string:r, pattern:"^Login name: GET", icase:FALSE ) ) {
  service_register( port:port, proto:"finger", message:"A finger service seems to be running on this port." );
  log_message( port:port, data:"A finger service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  0D 0A 49 6E 74 65 67 72 61 74 65 64 20 70 6F 72    ..Integrated por
# 0x10:  74 0D 0A 50 72 69 6E 74 65 72 20 54 79 70 65 3A    t..Printer Type:
# 0x20:  20 4C 65 78 6D 61 72 6B 20 4D 53 38 31 30 0D 0A     Lexmark MS810..
# 0x30:  50 72 69 6E 74 20 4A 6F 62 20 53 74 61 74 75 73    Print Job Status
# 0x40:  3A 20 4E 6F 20 4A 6F 62 20 43 75 72 72 65 6E 74    : No Job Current
# 0x50:  6C 79 20 41 63 74 69 76 65 0D 0A 50 72 69 6E 74    ly Active..Print
# 0x60:  65 72 20 53 74 61 74 75 73 3A 20 30 20 52 65 61    er Status: 0 Rea
# 0x70:  64 79 0D 0A                                        dy..
#
# nb: This is a "fake" finger server, showing the printer status.
# See find_service2.nasl as well
if( "Integrated port" >< r && "Printer Type" >< r && "Print Job Status" >< r ) {
  service_register( port:port, proto:"fingerd-printer", message:"A printer related finger service seems to be running on this port." );
  log_message( port:port, data:"A printer related finger service seems to be running on this port." );
  set_kb_item( name:"fingerd-printer/" + port + "/banner", value:ereg_replace( string:r, pattern:'(^\r\n|\r\n$)', replace:"" ) );
  exit( 0 );
}

# DICOM on 104/tcp and 11112/tcp
# nb: This is the A-ABORT message but not all services / implementations are responding to our probes.
#
# 0x00:  07 00 00 00 00 04 00 00 02 01                      ..........
#
# or (which seems to send different A-ABORT messages multiple times.
#
# 0x00:  07 00 00 00 00 04 00 00 00 00 07 00 00 00 00 04    ................
# 0x10:  00 00 02 02 07 00 00 00 00 04 00 00 02 02 07 00    ................
# 0x20:  00 00 00 04 00 00 02 02 07 00 00 00 00 04 00 00    ................
# 0x30:  02 02 07 00 00 00 00 04 00 00 02 02 07 00 00 00    ................
# 0x40:  00 04 00 00 02 02 07 00 00 00 00 04 00 00 02 02    ................
# 0x50:  07 00 00 00 00 04 00 00 02 02 07 00 00 00 00 04    ................
# 0x60:  00 00 02 02 07 00 00 00 00 04 00 00 02 02 07 00    ................
# 0x70:  00 00 00 04 00 00 02 02 07 00 00 00 00 04 00 00    ................
# 0x80:  02 02 07 00 00 00 00 04 00 00 02 02 07 00 00 00    ................
# 0x90:  00 04 00 00 02 02 07 00 00 00 00 04 00 00 02 02    ................
# 0xA0:  07 00 00 00 00 04 00 00 02 02 07 00 00 00 00 04    ................
# 0xB0:  00 00 02 02 07 00 00 00 00 04 00 00 02 02          ..............

if( rhexstr =~ "^(07000000000400000[0-2]0[0-6]){1,}$" ) {
  service_register( port:port, proto:"dicom", message:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
  log_message( port:port, data:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
  exit( 0 );
}

# 0x00:  4A 44 57 50 2D 48 61 6E 64 73 68 61 6B 65          JDWP-Handshake
if( r == "JDWP-Handshake" ) {
  service_register( port:port, proto:"jdwp", message:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  log_message( port:port, data:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  exit( 0 );
}

# nb: The same pattern is also checked in gb_rsync_remote_detect.nasl and find_service2.nasl.
# Please update those when updating the pattern here.
if( r =~ "^@RSYNCD: [0-9.]+" || r =~ "^You are not welcome to use rsync from " || r =~ "^rsync: (link_stat |error |.+unknown option)" ||
    r =~ "rsync error: (syntax or usage error|some files/attrs were not transferred) " || r =~ "rsync\s+version [0-9.]+\s+protocol version [0-9.]+" ) {
  service_register( port:port, proto:"rsync", message:"A service supporting the rsync protocol is running at this port." );
  log_message( port:port, data:"A service supporting the rsync protocol is running at this port." );
  exit( 0 );
}

# 0x00:  56 69 73 69 6F 6E 73 6F 66 74 20 41 75 64 69 74    Visionsoft Audit
# 0x10:  20 6F 6E 20 44 65 6D 61 6E 64 20 53 65 72 76 69     on Demand Servi
# 0x20:  63 65 0D 0A 56 65 72 73 69 6F 6E 3A 20 31 39 30    ce..Version: 190
# 0x30:  37 0D 0A 0D 0A 0A                                  7.....
# or:
#
# Visionsoft Audit on Demand Service
# Version: 303121750
if( "Visionsoft Audit on Demand Service" >< r ) {
  service_register( port:port, proto:"visionsoft-audit", message:"A Visionsoft Audit on Demand Service is running at this port." );
  log_message( port:port, data:"A Visionsoft Audit on Demand Service is running at this port." );
  exit( 0 );
}

# 0x00:  4F 4B 20 57 6F 72 6B 67 72 6F 75 70 53 68 61 72    OK WorkgroupShar
# 0x10:  65 20 32 2E 33 20 73 65 72 76 65 72 20 72 65 61    e 2.3 server rea
# 0x20:  64 79 0D 0A 45 52 52 4F 52 20 43 6F 6D 6D 61 6E    dy..ERROR Comman
# 0x30:  64 20 6E 6F 74 20 72 65 63 6F 67 6E 69 73 65 64    d not recognised
# 0x40:  0D 0A 45 52 52 4F 52 20 43 6F 6D 6D 61 6E 64 20    ..ERROR Command  # nb: space
# 0x50:  6E 6F 74 20 72 65 63 6F 67 6E 69 73 65 64 0D 0A    not recognised..
# 0x60:  45 52 52 4F 52 20 43 6F 6D 6D 61 6E 64 20 6E 6F    ERROR Command no
# 0x70:  74 20 72 65 63 6F 67 6E 69 73 65 64 0D 0A          t recognised..
#
# nb: See find_service_spontaneous.nasl as well
if( egrep( pattern:"^OK WorkgroupShare.+server ready", string:r, icase:FALSE ) ) {
  service_register( port:port, proto:"workgroupshare", message:"A WorkgroupShare Server is running at this port." );
  replace_kb_item( name:"workgroupshare/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"A WorkgroupShare Server is running at this port." );
  exit( 0 );
}

# HP Data Protector A.06.10: INET, internal build 611, built on 2008
# HPE Data Protector A.09.09: INET, internal build 114, built on Tuesday, March 28, 2017, 5:02 PM
# HPE Data Protector A.09.09: INET, internal build 115, built on Dienstag, 23. Mai 2017, 22:16
# HP OpenView Storage Data Protector A.06.00: INET, internal build 331
# HP OpenView Storage Data Protector A.05.50: INET, internal build 330
# HP OpenView Storage Data Protector A.05.00: INET, internal build 190, built on Tue Jul 16 17:37:32 2002.
# nb: See find_service2.nasl as well
if( r =~ "^HPE? (OpenView Storage )?Data Protector" ) {
  service_register( port:port, proto:"hp_dataprotector", message:"HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
  replace_kb_item( name:"hp_dataprotector/" + port + "/banner", value:chomp( r ) );
  log_message( port:port, data:"HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
  exit( 0 );
}

# On 9300/tcp
# 0x00:  54 68 69 73 20 69 73 20 6E 6F 74 20 61 20 48 54    This is not a HT
# 0x10:  54 50 20 70 6F 72 74                               TP port
# See find_service5.nasl as well
if( r =~ "^This is not a HTTP port$" ) {
  service_register( port:port, proto:"elasticsearch", message:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
  log_message( port:port, data:"An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
  exit( 0 );
}

# Port 264/tcp
#
# 0x00:  59 00 00 00                                        Y...
#
# or:
#
# 0x00:  51 00 00 00                                        Q...
#
# nb: See find_service2.nasl and find_service3.nasl as well
if( rhexstr =~ "^5[19]000000$" ) {
  service_register( port:port, proto:"fw1-topology", message:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  log_message( port:port, data:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  exit( 0 );
}

# Some spontaneous banners are coming slowly, so they are wrongly registered as answers to GET
if( r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
  service_report( port:port, svc:"hddtemp" );
  exit( 0 );
}

# Some services are responding with an SSL/TLS alert we currently don't recognize
# e.g. 0x00:  15 03 01 00 02 02 0A                               .......
# or 0x00:  15 03 01                                           ...
# See also "Alert Protocol format" in http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
if( rhexstr =~ "^15030[0-3]00020[1-2]..$" ||
    rhexstr =~ "^1500000732$" || # nb: e.g. Novell Zenworks prebootserver on 998/tcp
    rhexstr =~ "^150301$" ) {
  service_register( port:port, proto:"ssl", message:"A service responding with an SSL/TLS alert seems to be running on this port." );
  log_message( port:port, data:"A service responding with an SSL/TLS alert seems to be running on this port." );
  exit( 0 );
}

# PowerFolder P2P data (usually on port 1337/tcp where bytes 3 and 4 differ).
# At least bytes 5 to 15 don't differ on several tested server responses.
#
# 0x00:  00 00 09 03 1F 8B 08 00 00 00 00 00 00 00 7D 97    ..............}.
# 0x10:  09 70 13 D7 19 C7 9F E4 4B F2 81 41 BE 0D 3E 68    .p......K..A..>h
# 0x20:  71 6A 48 22 63 0C 1E 1C 9A 4E 7C C8 58 46 B6 B1    qjH"c....N|.XF..
# 0x30:  25 5B 58 E6 C8 A2 7D 92 D6 5E ED 4A BB 6F 75 D0    %[X...}..^.J.ou.
# 0x40:  29 A5 34 21 2D 9D 81 99 86 49 5B 28 A1 D0 36 A5    ).4!-....I[(..6.
# 0x50:  E0 00 85 98 30 E9 91 66 20 84 D6 25 21 43 12 12    ....0..f ..%!C..
# 0x60:  92 80 87 94 04 48 42 52 B0 C9 C5 C4 7D DF 93 64    .....HBR....}..d
# 0x70:  6C 7A AC E7 ED BE DF 3B BE F7 BD FF F7 0E 79 F0    lz.....;......y.
if( rhexstr =~ "0000....1f8b08000000000000007d" ) {
  service_register( port:port, proto:"powerfolder_data", message:"A PowerFolder P2P data service is running at this port." );
  log_message( port:port, data:"A PowerFolder P2P data service is running at this port." );
  exit( 0 );
}

exit( 0 );
