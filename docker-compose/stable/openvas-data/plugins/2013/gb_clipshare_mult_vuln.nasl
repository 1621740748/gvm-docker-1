###############################################################################
# OpenVAS Vulnerability Test
#
# ClipShare Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803440");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-03-18 14:25:41 +0530 (Mon, 18 Mar 2013)");
  script_name("ClipShare Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24790");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120792/");
  script_xref(name:"URL", value:"http://www.exploitsdownload.com/exploit/na/clipshare-414-sql-injection-plaintext-password");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to the password information and inject or manipulate SQL queries in the
  back-end database, allowing for the manipulation or disclosure of arbitrary
  data.");

  script_tag(name:"affected", value:"ClipShare Version 4.1.4");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - storing sensitive information in the /siteadmin/login.php file as plaintext

  - Input passed via the 'urlkey' parameter to ugroup_videos.php script is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with ClipShare and is prone to Multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/clipshare", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && ">ClipShare<" >< rcvRes ) {

    url = dir + "/ugroup_videos.php?urlkey=1' or (select if(5=5,0,3))-- 3='3";

    if( http_vuln_check( port:port, url:url, check_header:TRUE,
                         pattern:">ClipShare<" ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
