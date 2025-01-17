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

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145993");
  script_version("2021-05-28T07:04:47+0000");
  script_tag(name:"last_modification", value:"2021-05-28 07:04:47 +0000 (Fri, 28 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-21 03:50:07 +0000 (Fri, 21 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-29625");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer 4.6.1 < 4.8.1 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("adminer/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Adminer is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users of MySQL, MariaDB, PgSQL and SQLite are affected. XSS is
  in most cases prevented by strict CSP in all modern browsers. The only exception is when Adminer
  is using a pdo_ extension to communicate with the database (it is used if the native extensions
  are not enabled).");

  script_tag(name:"affected", value:"Adminer version 4.6.1 through 4.8.0.

  Note: In modern browsers with strict CSP only version 4.7.8 through 4.8.0 is affected.");

  script_tag(name:"solution", value:"Update to version 4.8.1 or later.");

  script_xref(name:"URL", value:"https://github.com/vrana/adminer/security/advisories/GHSA-2v82-5746-vwqc");

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

if (version_in_range(version: version, test_version:"4.6.1", test_version2: "4.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
