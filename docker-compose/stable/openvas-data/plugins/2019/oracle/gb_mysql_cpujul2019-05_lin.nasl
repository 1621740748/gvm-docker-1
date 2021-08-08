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

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142650");
  script_version("2021-02-12T10:44:24+0000");
  script_tag(name:"last_modification", value:"2021-02-12 10:44:24 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-07-24 01:44:19 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  # nb: From the vendor advisory: The update for CVE-2019-3822 also addresses CVE-2018-16890 and CVE-2019-3823.
  script_cve_id("CVE-2019-3822", "CVE-2018-16890", "CVE-2019-3823");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 5.7 <= 5.7.26 / 8.0 <= 8.0.15 Security Update (cpujul2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities in libcurl.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.7 through 5.7.26 and 8.0 through 8.0.15.");

  script_tag(name:"solution", value:"Update to version 5.7.27, 8.0.16 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2019");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.27", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.16", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);