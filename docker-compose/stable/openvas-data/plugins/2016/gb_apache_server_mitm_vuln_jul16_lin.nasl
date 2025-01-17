# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808632");
  script_version("2021-03-01T08:21:56+0000");
  script_cve_id("CVE-2016-5387");
  script_bugtraq_id(91816);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-07-26 18:40:57 +0530 (Tue, 26 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server Man-in-the-Middle Attack Vulnerability - July16 (Linux)");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a man-in-the-middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to 'CGI Servlet' does not
  protect applications from the presence of untrusted client data in the
  'HTTP_PROXY' environment variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to redirect an application's outbound HTTP traffic to an arbitrary
  proxy server via a crafted proxy header in an HTTP request.");

  script_tag(name:"affected", value:"Apache HTTP Server through 2.4.23.

  NOTE: Apache HTTP Server 2.2.32 is not vulnerable.");

  script_tag(name:"solution", value:"Update to version 2.4.24, or 2.2.32, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.apache.org/security/asf-httpoxy-response.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

##Version 2.2.32 is not vulnerable
if(version_is_equal(version:vers, test_version:"2.2.32"))
  exit(99);

if(version_is_less(version:vers, test_version:"2.4.24")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.24", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
