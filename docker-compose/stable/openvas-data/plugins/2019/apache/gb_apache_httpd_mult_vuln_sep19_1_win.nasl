# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114144");
  script_version("2021-03-01T08:21:56+0000");
  script_tag(name:"last_modification", value:"2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2019-10-18 14:35:48 +0200 (Fri, 18 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-10092", "CVE-2019-10098");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.0 - 2.4.40 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Apache HTTP server is prone to multiple vulnerabilities:

  - A limited cross-site scripting issue affecting the mod_proxy error page. An attacker
  could cause the link on the error page to be malformed and instead point to a page of
  their choice. This would be exploitable where a server was set up with proxying enabled
  but was misconfigured in such a way that the Proxy Error page was displayed. (CVE-2019-10092)

  - Redirects configured with mod_rewrite that were intended to be self referential
  might be fooled by encoded newlines and redirect instead to an unexpected URL within
  the request URL. (CVE-2019-10098)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.0 to 2.4.40.");

  script_tag(name:"solution", value:"Update to version 2.4.41 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
