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
  script_oid("1.3.6.1.4.1.25623.1.0.146337");
  script_version("2021-08-03T07:24:09+0000");
  script_tag(name:"last_modification", value:"2021-08-03 07:24:09 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-21 04:55:35 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-32667");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 XSS Vulnerability (TYPO3-CORE-SA-2021-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Failing to properly encode Page TSconfig settings, the
  corresponding page preview module (Web>View) is vulnerable to persistent cross-site scripting.
  A valid backend user account is needed to exploit this vulnerability.");

  script_tag(name:"affected", value:"TYPO3 version 9.0.0 through 9.5.27, 10.0.0 through 10.4.17 and
  11.0.0 through 11.3.0.");

  script_tag(name:"solution", value:"Update to version 9.5.28, 10.4.18, 11.3.1 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2021-009");

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

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
