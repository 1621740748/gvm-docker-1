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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145680");
  script_version("2021-03-30T04:07:40+0000");
  script_tag(name:"last_modification", value:"2021-03-30 04:07:40 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-30 03:45:02 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-21370");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 XSS Vulnerability (TYPO3-CORE-SA-2021-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that content elements of type menu are vulnerable
  to an XSS when their referenced items get previewed in the page module. A valid backend user account is
  needed to exploit this vulnerability.

  The affected code is only executed if an extension is used that actually leverages the type menu. By default
  this is not available by the Core.");

  script_tag(name:"affected", value:"TYPO3 version 7.0.0 through 7.6.50, 8.0.0 through 8.7.39, 9.0.0 through
  9.5.16, 10.0.0 through 10.4.1 and 11.0.0 through 11.1.0.");

  script_tag(name:"solution", value:"Update to version 7.6.51, 8.7.40, 9.5.25, 10.4.14, 11.1.1 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2021-008");

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

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.6.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.51", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
