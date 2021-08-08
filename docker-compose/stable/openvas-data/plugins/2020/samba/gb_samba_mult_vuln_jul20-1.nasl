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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108814");
  script_version("2020-11-12T09:56:04+0000");
  script_tag(name:"last_modification", value:"2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-07-06 05:44:03 +0000 (Mon, 06 Jul 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-10745", "CVE-2020-14303");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple DoS Vulnerabilities (CVE-2020-10745, CVE-2020-14303)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to two denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Compression of replies to NetBIOS over TCP/IP name resolution and
  DNS packets (which can be supplied as UDP requests) can be abused to consume excessive amounts of CPU
  on the Samba AD DC (only). (CVE-2020-10745)

  - The AD DC NBT server in Samba 4.0 will enter a CPU spin and not process further requests once it
  receives an empty (zero-length) UDP packet to port 137. (CVE-2020-14303)");

  script_tag(name:"affected", value:"All Samba versions since 4.0.0.");

  script_tag(name:"solution", value:"Update to version 4.10.17, 4.11.11, 4.12.4 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-10745.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-14303.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.10.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.10.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.11.0", test_version2: "4.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.11.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.12.0", test_version2: "4.12.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
