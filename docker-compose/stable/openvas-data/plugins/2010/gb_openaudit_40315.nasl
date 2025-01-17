###############################################################################
# OpenVAS Vulnerability Test
#
# Open-Audit Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = 'cpe:/a:opmantek:open-audit';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100654");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
  script_bugtraq_id(40315);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Open-Audit Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40315");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_open_audit_detect.nasl");
  script_mandatory_keys("open-audit/detected");

  script_tag(name:"summary", value:"Open-Audit is prone to multiple vulnerabilities, including a local
  file-include vulnerability and multiple SQL-injection, cross-site scripting, and authentication-bypass
  vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to steal cookie-based
  authentication credentials, compromise the application, access or modify data, exploit latent vulnerabilities
  in the underlying database, bypass security restrictions, obtain potentially sensitive information,
  perform unauthorized actions, or execute arbitrary local scripts in the context of the webserver process,
  other attacks are also possible.");

  script_tag(name:"affected", value:"Open-Audit 20081013 and 20091223-RC are vulnerable, other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/list.php?view=%3Cscript%3Ealert(%27XSS-Test%27)%3B%3C%2Fscript%3E";

if (http_vuln_check(port:port, url:url,pattern:"<script>alert\('XSS-Test'\);</script>", check_header:TRUE)) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit(0);
}

exit(0);
