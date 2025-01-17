# Copyright (C) 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10839");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2029");
  script_bugtraq_id(3786);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP.EXE / Apache HTTP Server Win32 Arbitrary File Reading Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_php_http_detect.nasl", "secpod_apache_http_server_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/detected", "apache/http_server/http/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2002/Jan/1003104.html");

  script_tag(name:"solution", value:"Obtain the latest version of PHP.");

  script_tag(name:"summary", value:"A configuration vulnerability exists for PHP.EXE cgi
  running on Apache HTTP Server for Win32 platforms.");

  script_tag(name:"insight", value:"It is reported that the installation text recommends
  configuration options in httpd.conf that create a security vulnerability, allowing
  arbitrary files to be read from the host running PHP. Remote users can directly execute
  the PHP binary:

  /php/php.exe?c:\winnt\win.ini");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

files = traversal_files( "windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( find:"/", string:file, replace:"\" );
  url  = "/php/php.exe?c:\" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
