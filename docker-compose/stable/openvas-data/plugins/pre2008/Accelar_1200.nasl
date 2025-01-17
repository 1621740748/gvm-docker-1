###############################################################################
# OpenVAS Vulnerability Test
#
# Bay Networks Accelar 1200 Switch found with default password
#
# Authors:
# Charles Thier <cthier@thethiers.net>
#
# Copyright:
# Copyright (C) 2005 Charles Thier
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
  script_oid("1.3.6.1.4.1.25623.1.0.18415");
  script_version("2020-06-09T14:44:58+0000");
  script_tag(name:"last_modification", value:"2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Bay Networks Accelar 1200 Switch found with default password");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Charles Thier");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports(23); # the port can't be changed on the device
  script_mandatory_keys("telnet/bay_networks/accelar_1200/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value:"no");

  script_tag(name:"solution", value:"Telnet to this switch and change the default password.");

  script_tag(name:"summary", value:"The remote host appears to be an Bay Networks Accelar 1200 Switch with
  its default password set.");

  script_tag(name:"impact", value:"The attacker could use this default password to gain remote access
  to your switch. This password could also be potentially used to
  gain other sensitive information about your network from the switch.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");
include("misc_func.inc");
include("dump.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) ) exit( 0 );

port = 23; # the port can't be changed on the device
if( ! get_port_state( port ) )
  exit( 0 );

banner = telnet_get_banner( port:port );
if( ! banner || "Accelar 1200" >!< banner )
  exit( 0 );

p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );
if( "yes" >< p ) {
  clist = try();
} else {
  clist = try(vendor:"accelar");
}
if( ! clist ) exit( 0 );

foreach credential( clist ) {

  # Handling of user uploaded credentials which requires to escape a ';' or ':'
  # in the user/password so it doesn't interfere with our splitting below.
  credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
  credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

  user_pass = split( credential, sep:":", keep:FALSE );
  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) {
    # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
    # GSA is stripping ';' from the NVT description. Keeping both in here
    # for backwards compatibility with older scan configs.
    user_pass = split( credential, sep:";", keep:FALSE );
    if( isnull( user_pass[0] ) || isnull( user_pass[1] ) )
      continue;
  }

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
  pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
  user = str_replace( string:user, find:"#sem_new#", replace:":" );
  pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

  if( tolower( pass ) == "none" ) pass = "";

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  answer = recv( socket:soc, length:4096 );
  if( "ogin:" >< answer ) {
    send( socket:soc, data:string( user, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );
    send( socket:soc, data:string( pass, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );

    if( "Accelar-1200" >< answer ) {
      security_message( port:port, data:"It was possible to login with the credentials '" + user + ":" + pass + "'." );
    }
  }
  close( soc );
}

exit( 0 );
