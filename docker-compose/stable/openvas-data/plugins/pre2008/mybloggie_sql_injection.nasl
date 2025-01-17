###############################################################################
# OpenVAS Vulnerability Test
#
# myBloggie Multiple Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.18209");
  script_version("2021-03-11T10:58:32+0000");
  script_tag(name:"last_modification", value:"2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1140", "CVE-2005-1498", "CVE-2005-1499", "CVE-2005-1500");
  script_bugtraq_id(13192, 13507);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("myBloggie Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://mywebland.com/forums/viewtopic.php?t=180");

  script_tag(name:"solution", value:"Patches have been provided by the vendor and are
  available at the referenced URL.");

  script_tag(name:"affected", value:"myBloggie 2.1.1 is known to be affected.");

  script_tag(name:"summary", value:"myBloggie is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Full Path Disclosure: Due to an improper sanitization of the post_id parameter, it's
  possible to show the full path by sending a simple request.

  - Cross-Site Scripting (XSS): Input passed to 'year' parameter in viewmode.php is not
  properly sanitised before being returned to users. This can be exploited execute
  arbitrary HTML and script code in a user's browser session in context of a
  vulnerable site.

  - SQL Injection: When myBloggie get the value of the 'keyword' parameter and put it in
  the SQL query, don't sanitise it. So a remote user can do SQL injection attacks.");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);
  if(!res || 'mywebland.com">myBloggie ' >!< res)
    continue;

  url = dir + "/index.php?mode=viewid&post_id=1'";

  if(http_vuln_check(port:port, url:url, pattern:"You have an error in your SQL syntax")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
