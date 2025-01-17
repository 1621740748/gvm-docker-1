###############################################################################
# OpenVAS Vulnerability Test
#
# Sollae Systems Devices Default Telnet Credentials / Unrestricted Access
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112323");
  script_version("2021-05-26T06:00:13+0200");
  script_cve_id("CVE-2018-12924");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sollae Systems Devices Default Telnet Credentials / Unrestricted Access");
  script_tag(name:"last_modification", value:"2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-24 15:09:00 +0000 (Fri, 24 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-07-04 11:32:00 +0200 (Wed, 04 Jul 2018)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97374");

  script_tag(name:"summary", value:"Sollae Systems Serial-Ethernet-Module and Remote-I/O-Device-Server devices
  have a default telnet password set or no password at all.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information.");

  script_tag(name:"vuldetect", value:"Connects to the telnet service and tries to login with default password.");

  script_tag(name:"solution", value:"It is recommended to disable the telnet access.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port, timeout:10 );

if( ( "Sollae Systems" >< banner && "Management Console" >< banner ) || ( "MIC" >< banner && "Copyright(c) Sollae Systems Co.,Ltd." >< banner ) ) {
  password = "sollae";
  access = FALSE;
  vuln = FALSE;

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  recv = recv( socket:soc, length:2048, timeout:10 );

  if ( ( "Sollae Systems" >< recv && "Management Console" >< recv && "lsh>" >< recv ) || ( "MIC" >< recv && "Copyright(c) Sollae Systems Co.,Ltd." >< recv && "msh>" >< recv ) ) {
    access = TRUE;
    report = "It was possible to gain unrestricted telnet access without entering credentials.";
  } else if ( ( "Sollae Systems" >< recv && "Management Console" >< recv || "MIC" >< recv && "Copyright(c) Sollae Systems Co.,Ltd." ) && "password:" >< recv ) {
    send( socket:soc, data:password + '\r\n' );
    recv = recv( socket:soc, length:128, timeout:10 );

    if ( "lsh>" >< recv || "msh>" >< recv ) {
      access = TRUE;
      report = "It was possible to gain telnet access via the default password 'sollae'.";
    }
  }

  if ( access ) {
    send( socket:soc, data:'st net\r\n' );
    recv = recv( socket:soc, length:2048, timeout:10 );

    if( "proto" >< recv && "peer address" >< recv )
      vuln = TRUE;
  }

  send( socket:soc, data:'exit\r\n' );
  close( soc );

  if( vuln ) {
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
