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
  script_oid("1.3.6.1.4.1.25623.1.0.145958");
  script_version("2021-05-17T07:13:15+0000");
  script_tag(name:"last_modification", value:"2021-05-17 07:13:15 +0000 (Mon, 17 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 06:51:47 +0000 (Mon, 17 May 2021)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:P");

  script_cve_id("CVE-2020-26229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 XXE Vulnerability (TYPO3-CORE-SA-2020-012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to an XML External Entity (XXE) vulnerability in
  the Dasboard widget.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that RSS widgets are susceptible to XML
  external entity processing.

  This vulnerability is reasonable, but is theoretical - it was not possible to actually reproduce
  the vulnerability with current PHP versions of supported and maintained system distributions.

  At least with libxml2 version 2.9, the processing of XML external entities is disabled per
  default - and cannot be exploited. Besides that, a valid backend user account is needed.");

  script_tag(name:"affected", value:"TYPO3 version 10.4.0 through 10.4.9.");

  script_tag(name:"solution", value:"Update to version 10.4.10 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-012");

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

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
