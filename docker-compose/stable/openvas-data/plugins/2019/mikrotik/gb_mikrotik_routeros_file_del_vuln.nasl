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

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142803");
  script_version("2020-10-09T06:15:40+0000");
  script_tag(name:"last_modification", value:"2020-10-09 06:15:40 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-08-27 05:11:26 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2019-15055");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS File Deletion Vulnerability (CVE-2019-15055)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is vulnerable to an authenticated file deletion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS improperly handles the disk name, which allows authenticated
  users to delete arbitrary files.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to reset credential storage, which
  allows them access to the management interface as an administrator without authentication.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.44.6 (LTS), 6.45.5 (Stable)
  and 6.46beta34 (Testing).");

  script_tag(name:"solution", value:"Update to version 6.44.6 (LTS), 6.45.5 (Stable), 6.46beta34
  (Testing) or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-19-108");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=151603");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=153379");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/testing-release-tree");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.44.6") ||
    version_in_range(version: version, test_version: "6.45.0", test_version2: "6.45.4") ||
    version_in_range(version: version, test_version: "6.46beta1", test_version2: "6.46beta33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44.6 / 6.45.5 / 6.46beta34");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
