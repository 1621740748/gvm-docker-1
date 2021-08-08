# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146119");
  script_version("2021-06-28T07:09:08+0000");
  script_tag(name:"last_modification", value:"2021-06-28 07:09:08 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-15 01:54:29 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-22915");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Brute-Force Protection Vulnerability (NC-SA-2021-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a vulnerability in the brute-force
  protection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nextcloud server is vulnerable to brute force attacks due to
  lack of inclusion of IPv6 subnets in rate-limiting considerations. This could potentially result
  in an attacker bypassing rate-limit controls such as the Nextcloud brute-force protection.");

  script_tag(name:"affected", value:"Nextcloud server prior to versions 19.0.11, 20.x through
  20.0.9 and 21.x through 21.0.1.");

  script_tag(name:"solution", value:"Update to version 19.0.11, 20.0.10, 21.0.2 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2021-009");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "19.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0.0", test_version2: "20.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.0.0", test_version2: "21.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
