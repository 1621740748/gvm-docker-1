###############################################################################
# OpenVAS Vulnerability Test
#
# JServ Cross Site Scripting
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10957");
  script_version("2021-02-25T13:36:35+0000");
  script_tag(name:"last_modification", value:"2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("JServ Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"solution", value:"Update to the latest version of JServ available at the linked reference.

  Also consider switching from JServ to Apache Tomcat, since JServ is no longer maintained.");

  script_tag(name:"summary", value:"The remote web server is vulnerable to a cross-site scripting issue.

  Older versions of JServ (including the version shipped with Oracle9i App
  Server v1.0.2) are vulnerable to a cross site scripting attack using a
  request for a non-existent .JSP file.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( !banner || "Apache" >!< banner )
  exit( 0 );

url = "/a.jsp/<SCRIPT>alert(document.domain)</SCRIPT>";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( !res )
  exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
