# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143732");
  script_version("2021-02-12T11:09:59+0000");
  script_tag(name:"last_modification", value:"2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-04-20 03:41:06 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-2780", "CVE-2020-2804", "CVE-2020-2760", "CVE-2020-2762", "CVE-2020-2893",
                "CVE-2020-2895", "CVE-2020-2898", "CVE-2020-2903", "CVE-2020-2896", "CVE-2020-2765",
                "CVE-2020-2892", "CVE-2020-2897", "CVE-2020-2923", "CVE-2020-2924", "CVE-2020-2901",
                "CVE-2020-2928", "CVE-2020-2904", "CVE-2020-2925", "CVE-2020-2759", "CVE-2020-2763",
                "CVE-2020-2812", "CVE-2020-2926", "CVE-2020-2921", "CVE-2020-2930");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.19 Security Update (cpuapr2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0 through 8.0.19.");

  script_tag(name:"solution", value:"Update to version 8.0.20 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2020");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);