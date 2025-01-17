###############################################################################
# OpenVAS Vulnerability Test
#
# ZTE ZXR10 Router Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107254");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-10931");

  script_name("ZTE ZXR10 Router Multiple Vulnerabilities");

  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-11-09 10:23:00 +0200 (Thu, 09 Nov 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/zte/zxr10/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.palada.net/index.php/2017/10/23/news-3819/");

  script_tag(name:"summary", value:"ZTE ZXR10 Router has a backdoor account with hard-coded credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");
  script_tag(name:"solution", value:"Update to version 3.00.40. For more details.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1008262");
  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( !banner || banner !~ "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation"  )
  exit( 0 );

creds = make_list("who;who", "zte;zte", "ncsh;ncsh");

foreach cred (creds)
{

  user_name = split(cred, sep: ";", keep: FALSE);
  name = user_name[0];
  pass = user_name[1];

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  recv = recv( socket:soc, length:2048 );

  if ( "Username:" >< recv )
  {
    send( socket:soc, data: tolower( name ) + '\r\n' );
    recv = recv( socket:soc, length:128 );

    if( "Password:" >< recv )
    {
      send( socket:soc, data: pass + '\r\n\r\n' );
      recv = recv( socket:soc, length:1024 );

      if ( !isnull(recv) )
      {
        send( socket:soc, data: '?\r\n' );
        recv = recv( socket:soc, length:1024 );

        if ( "Exec commands:" >< recv)
        {
            VULN = TRUE;
            report = 'It was possible to login via telnet using the following credentials:\n\n';
            report += 'Username: ' + name + ', Password: ' + pass;
            break;
        }
      }
    }
  }
  close( soc );
}


if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
