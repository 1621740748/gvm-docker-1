# OpenVAS Vulnerability Test
# Description: YaPiG Multiple Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18523");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1881", "CVE-2005-1882", "CVE-2005-1883", "CVE-2005-1884", "CVE-2005-1885", "CVE-2005-1886");
  script_bugtraq_id(13871, 13874, 13875, 13876, 13877);
  script_xref(name:"OSVDB", value:"17115");
  script_xref(name:"OSVDB", value:"17116");
  script_xref(name:"OSVDB", value:"17117");
  script_xref(name:"OSVDB", value:"17118");
  script_xref(name:"OSVDB", value:"17119");
  script_xref(name:"OSVDB", value:"17120");
  script_xref(name:"OSVDB", value:"17121");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("YaPiG Multiple Flaws");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to YaPiG 0.95b or later.");

  script_tag(name:"summary", value:"The remote web server contains a PHP application that is affected by
multiple flaws.

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP.

The installed version of YaPiG is vulnerable to multiple flaws:

  - Remote and local file inclusion.

  - Cross-site scripting and HTML injection flaws through 'view.php'.

  - Directory traversal flaw through 'upload.php'.");
  script_xref(name:"URL", value:"http://secwatch.org/advisories/secwatch/20050530_yapig.txt");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/yapig", "/gallery", "/photos", "/photo", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) continue;

  #Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
  if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-4][a-z]|5a))", string:res)) {
    security_message( port:port );
    exit(0);
  }
}

exit( 99 );
