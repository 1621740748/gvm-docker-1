###############################################################################
# OpenVAS Vulnerability Test
#
# SSH Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2006 SecuriTeam
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10267");
  script_version("2021-06-21T07:41:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-21 07:41:28 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_name("SSH Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service_spontaneous.nasl", "find_service6.nasl",
                      "ssh_authorization_init.nasl", "global_settings.nasl");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:"This detects the SSH Server's type and version by connecting to the server
  and processing the buffer received.

  This information gives potential attackers additional information about the system they are attacking.
  Versions and Types should be omitted where possible.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");

login      = kb_ssh_login();
passwd     = kb_ssh_password();
privkey    = kb_ssh_privatekey();
passphrase = kb_ssh_passphrase();
activeauth = get_kb_item( "global_settings/authenticated_scans_disabled" );

if( login && ( passwd || privkey ) && ! activeauth ) {
  report_passwd = "SSH password/private key configured for this task";
} else {
  vt_strings = get_vt_strings();
  login  = vt_strings["default"];
  passwd = vt_strings["default"];
  report_passwd = passwd;
}

port = ssh_get_port( default:22 );
server_banner = ssh_get_serverbanner( port:port );
if( ! server_banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( soc ) {
  login_banner = ssh_get_login_banner( port:port, sock:soc, login:login, passwd:passwd, privkey:privkey, keypassphrase:passphrase );
  sess_id      = ssh_session_id_from_sock( soc );
  if( sess_id )
    supported = ssh_get_supported_authentication( sess_id:sess_id );
  close( soc );
}

set_kb_item( name:"ssh_or_telnet/banner/available", value:TRUE );
set_kb_item( name:"ssh/server_banner/available", value:TRUE );
set_kb_item( name:"ssh/server_banner/" + port + "/available", value:TRUE );

text = 'Remote SSH server banner: ' + server_banner + '\n';

text += 'Remote SSH supported authentication: ';
if( supported ) {
  set_kb_item( name:"SSH/supportedauth/" + port, value:supported );
  text += supported + '\n';
} else {
  text += '(not available)\n';
}

text += 'Remote SSH text/login banner: ';
if( login_banner ) {
  text += '\n\n--- separator ---\n\n' + login_banner + '\n\n--- separator ---';
  set_kb_item( name:"ssh/login_banner/available", value:TRUE );
  set_kb_item( name:"ssh/login_banner/" + port + "/available", value:TRUE );
} else {
  text += '(not available)';
}

if( server_banner =~ "SSH-.+OpenSSH" ) {
  set_kb_item( name:"ssh/openssh/detected", value:TRUE );
  set_kb_item( name:"ssh/openssh/" + port + "/detected", value:TRUE );
  set_kb_item( name:"ssh/openssh_or_dropbear/detected", value:TRUE );
  guess += '\n- OpenSSH';
}

if( "Foxit-WAC-Server" >< server_banner ) {
  set_kb_item( name:"ssh/foxit/wac-server/detected", value:TRUE );
  set_kb_item( name:"ssh_or_telnet/foxit/wac-server/detected", value:TRUE );
  set_kb_item( name:"ssh/foxit/wac-server/" + port + "/detected", value:TRUE );
  guess += '\n- Foxit Software WAC Server';
}

if( server_banner =~ "SSH-.+dropbear" ) {
  set_kb_item( name:"ssh/dropbear_ssh/detected", value:TRUE );
  set_kb_item( name:"ssh/dropbear_ssh/" + port + "/detected", value:TRUE );
  set_kb_item( name:"ssh/openssh_or_dropbear/detected", value:TRUE );
  guess += '\n- Dropbear SSH';
}

if( egrep( string:server_banner, pattern:"^SSH-[0-9.]+-SSF" ) ) {
  set_kb_item( name:"ssh/ssf/detected", value:TRUE );
  set_kb_item( name:"ssh/ssf/" + port + "/detected", value:TRUE );
  guess += '\n- SSF';
}

if( server_banner =~ "^SSH-.*libssh" ) {
  set_kb_item( name:"ssh/libssh/detected", value:TRUE );
  set_kb_item( name:"ssh/libssh/" + port + "/detected", value:TRUE );
  guess += '\n- SSH implementation using the https://www.libssh.org/ library';
}

if( server_banner =~ "SSH\-.*ReflectionForSecureIT" ) {
  set_kb_item( name:"ssh/reflection/secureit/detected", value:TRUE );
  set_kb_item( name:"ssh/reflection/secureit/" + port + "/detected", value:TRUE );
  guess += '\n- Reflection for Secure IT';
}

if( server_banner =~ "SSH-[0-9.]+-Comware" ) {
  set_kb_item( name:"ssh/hp/comware/detected", value:TRUE );
  set_kb_item( name:"ssh/hp/comware/" + port + "/detected", value:TRUE );
  guess += '\n- HP Comware Device';
}

if( "SSH-2.0-Go" >< server_banner ) {
  set_kb_item( name:"ssh/golang/ssh/detected", value:TRUE );
  set_kb_item( name:"ssh/golang/ssh/" + port + "/detected", value:TRUE );
  guess += '\n- SSH implementation using the Golang SSH library';
}

if( ereg( pattern:'SSH-[0-9.-]+[ \t]+RemotelyAnywhere', string:server_banner ) ) {
  set_kb_item( name:"ssh/remotelyanywhere/detected", value:TRUE );
  set_kb_item( name:"ssh/remotelyanywhere/" + port + "/detected", value:TRUE );
  guess += '\n- RemotelyAnywhere';
}

if( server_banner =~ "SSH.*xlightftpd" ) {
  set_kb_item( name:"ssh/xlightftpd/detected", value:TRUE );
  set_kb_item( name:"ssh/xlightftpd/" + port + "/detected", value:TRUE );
  guess += '\n- SSH service of Xlight FTP';
}

if( egrep( pattern:"SSH.+WeOnlyDo", string:server_banner ) ) {
  set_kb_item( name:"ssh/freesshd/detected", value:TRUE );
  set_kb_item( name:"ssh/freesshd/" + port + "/detected", value:TRUE );
  guess += '\n- FreeSSHD';
}

if( server_banner =~ "SSH.*Bitvise SSH Server \(WinSSHD\)" ) {
  set_kb_item( name:"ssh/bitvise/ssh_server/detected", value:TRUE );
  set_kb_item( name:"ssh/bitvise/ssh_server/" + port + "/detected", value:TRUE );
  guess += '\n- Bitvise SSH Server';
}

if( egrep( pattern:"SSH.+SysaxSSH", string:server_banner ) ) {
  set_kb_item( name:"ssh/sysaxssh/detected", value:TRUE );
  set_kb_item( name:"ssh/sysaxssh/" + port + "/detected", value:TRUE );
  guess += '\n- Sysax Multi Server SSH Component';
}

if( egrep( pattern:"SSH.+Serv-U", string:server_banner ) ) {
  set_kb_item( name:"ssh/serv-u/detected", value:TRUE );
  set_kb_item( name:"ssh/serv-u/" + port + "/detected", value:TRUE );
  guess += '\n- Serv-U SSH';
}

if( "SSH-2.0-ROSSSH" >< server_banner ) {
  set_kb_item( name:"ssh/mikrotik/routeros/detected", value:TRUE );
  set_kb_item( name:"ssh/mikrotik/routeros/" + port + "/detected", value:TRUE );
  guess += '\n- MikroTik RouterOS';
}

if( server_banner =~ "^SSH-[0-9.]+-Cisco-[0-9.]+" ) {
  set_kb_item( name:"ssh/cisco/ios/detected", value:TRUE );
  set_kb_item( name:"ssh/cisco/ios/" + port + "/detected", value:TRUE );
  guess += '\n- Cisco IOS';
}

if( egrep( pattern:"SSH.+Data ONTAP SSH", string:server_banner ) ) {
  set_kb_item( name:"ssh/netapp/data_ontap/detected", value:TRUE );
  set_kb_item( name:"ssh/netapp/data_ontap/" + port + "/detected", value:TRUE );
  guess += '\n- NetApp Data ONTAP';
}

if( egrep( pattern:"SSH.+-lancom", string:server_banner ) ) {
  set_kb_item( name:"ssh/lancom/detected", value:TRUE );
  set_kb_item( name:"ssh/lancom/" + port + "/detected", value:TRUE );
  guess += '\n- LANCOM Device';
}

if( egrep( pattern:"SSH.+-Zyxel SSH server", string:server_banner ) ) {
  set_kb_item( name:"ssh/zyxel_usg/detected", value:TRUE );
  set_kb_item( name:"ssh/zyxel_usg/" + port + "/detected", value:TRUE );
  guess += '\n- Zyxel USG Device';
}

# SSH-2.0-Greenbone_7.4p2gb Greenbone OS 6.0
#
# Older releases of GOS had also a pre-login banner like e.g.:
#
# Welcome to Greenbone OS 1.6
#
if( egrep( pattern:"SSH.+Greenbone OS", string:server_banner ) || "Welcome to Greenbone OS" >< login_banner ) {
  set_kb_item( name:"ssh/greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"ssh/greenbone/gos/" + port + "/detected", value:TRUE );
  guess += '\n- Greenbone OS (GOS)';
}

# SSH-2.0-HUAWEI-1.5
if( server_banner == "SSH-2.0--" || "SSH-2.0-HUAWEI-" >< server_banner || server_banner == "SSH-1.99--" ) {
  set_kb_item( name:"ssh/huawei/vrp/detected", value:TRUE );
  set_kb_item( name:"ssh/huawei/vrp/" + port + "/detected", value:TRUE );
  guess += '\n- Huawei Versatile Routing Platform (VRP)';
}

if( server_banner =~ "SSH-.+OpenSSL" ) {
  set_kb_item( name:"ssh/openssl/detected", value:TRUE );
  set_kb_item( name:"ssh/openssl/" + port + "/detected", value:TRUE );
  guess += '\n- OpenSSL';
}

if( login_banner && "Riverbed" >< login_banner ) {

  if( "Riverbed SteelHead" >< login_banner ) { # gb_riverbed_steelhead_ssh_detect.nasl
    set_kb_item( name:"ssh/riverbed/steelhead/detected", value:TRUE );
    set_kb_item( name:"ssh/riverbed/steelhead/" + port + "/detected", value:TRUE );
    guess += '\n- Riverbed SteelHead';
  }

  if( "Riverbed Cascade" >< login_banner ) { # gb_riverbed_steelcentral_ssh_detect.nasl
    set_kb_item( name:"ssh/riverbed/steelcentral/detected", value:TRUE );
    set_kb_item( name:"ssh/riverbed/steelcentral/" + port + "/detected", value:TRUE );
    set_kb_item( name:"ssh/riverbed/cascade/detected", value:TRUE );
    set_kb_item( name:"ssh/riverbed/cascade/" + port + "/detected", value:TRUE );
    guess += '\n- Riverbed Cascade/SteelCentral';
  }

  # If one of the above doesn't match we still want to report an unknown Riverbed Product.
  if( "Riverbed" >!< guess ) {
    set_kb_item( name:"ssh/riverbed/unknown_product/detected", value:TRUE );
    set_kb_item( name:"ssh/riverbed/unknown_product/" + port + "/detected", value:TRUE );
    guess += '\n- Unknown Riverbed Product';
  }
}

if( login_banner && "viptela" >< login_banner && "OpenSSH" >< server_banner ) {
  set_kb_item( name:"ssh/cisco/vmanage/detected", value:TRUE );
  set_kb_item( name:"ssh/cisco/vmanage/" + port + "/detected", value:TRUE );
  guess += '\n- Cisco SD-WAN vManage';
}

if( login_banner && "VMware vCenter Server Appliance" >< login_banner && "OpenSSH" >< server_banner ) {
  set_kb_item( name:"ssh/vmware/vcenter/detected", value:TRUE );
  set_kb_item( name:"ssh/vmware/vcenter/" + port + "/detected", value:TRUE );
  guess += '\n- VMware vCenter Server Appliance';
}

if( strlen( guess ) > 0 )
  text += '\n\nThis is probably:\n' + guess;

text += '\n\nConcluded from remote connection attempt with credentials:\n';
text += '\nLogin:    ' + login;
text += '\nPassword: ' + report_passwd;

service_register( port:port, proto:"ssh", message:text );
log_message( port:port, data:text );
exit( 0 );
