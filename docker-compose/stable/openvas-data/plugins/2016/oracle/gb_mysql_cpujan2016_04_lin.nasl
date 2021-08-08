# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812170");
  script_version("2021-02-12T11:09:59+0000");
  script_cve_id("CVE-2016-0609", "CVE-2016-0608", "CVE-2016-0606", "CVE-2016-0600", "CVE-2016-0598",
                "CVE-2016-0597", "CVE-2016-0546", "CVE-2016-0505");
  script_bugtraq_id(81258, 81226, 81188, 81182, 81151, 81066, 81088);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-11-22 13:16:06 +0530 (Wed, 22 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Server <= 5.5.46 / 5.6 <= 5.6.27 / 5.7.9 Security Update (cpujan2016) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exist in the 'MySQL Server' component via
  unknown vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker
  to affect confidentiality, integrity, and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.5.46 and prior, 5.6 through 5.6.27 and version 5.7.9.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2016.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2016");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.5.46") ||
   version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.27") ||
   version_is_equal(version:vers, test_version:"5.7.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See the referenced vendor advisory", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);