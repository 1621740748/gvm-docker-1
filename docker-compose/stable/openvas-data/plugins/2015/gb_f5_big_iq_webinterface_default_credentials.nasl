###############################################################################
# OpenVAS Vulnerability Test
#
# F5 Networks BIG-IQ Webinterface Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

CPE = "cpe:/a:f5:big-iq_centralized_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105166");
  script_version("2019-11-14T01:12:31+0000");
  script_tag(name:"last_modification", value:"2019-11-14 01:12:31 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2015-01-12 15:25:49 +0100 (Mon, 12 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("F5 Networks BIG-IQ Webinterface Default Credentials");

  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");

  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_default_credentials_options.nasl");

  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_f5_big_iq_consolidation.nasl");

  script_require_ports("Services/www", 443);
  script_mandatory_keys("f5/big_iq/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote F5 BIG-IQ web interface is prone to a default account authentication
  bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if ( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if ( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

pd = '{"username":"admin","password":"admin","needsToken":true}';

req = http_post( port:port, item:'/mgmt/shared/authn/login', data:pd );
res = http_keepalive_send_recv( port:port, data:req );

if( "Authentication failed" >!< res && ( "loginReference" >< res && "token" >< res && '"username":"admin"' >< res) ) {
  report = "It was possible to authenticate with the 'admin:admin' credentials.";
  security_message( port:port , data:report );
  exit( 0 );
}

exit( 99 );
