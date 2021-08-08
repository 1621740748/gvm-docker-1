##############################################################################
# OpenVAS Vulnerability Test
#
# EMC Isilon OneFS Path Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:dell:emc_isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106701");
  script_version("2020-04-06T06:18:10+0000");
  script_tag(name:"last_modification", value:"2020-04-06 06:18:10 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-03-30 11:44:57 +0700 (Thu, 30 Mar 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-4980");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_emc_isilon_onefs_consolidation.nasl");
  script_mandatory_keys("dell/emc_isilon/onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by a path traversal vulnerability that may
  potentially be exploited by attackers to compromise the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Isilon OneFS is affected by a path traversal vulnerability. Attackers
  could potentially exploit this vulnerability to access unauthorized information by supplying specially crafted
  strings in input parameters of the application.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.1.0 - 7.1.1.10, 7.2.0 - 7.2.1.3, 8.0.0 - 8.0.0.1.");

  script_tag(name:"solution", value:"Update to version 7.1.1.11, 7.2.1.4, 8.0.0.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/540338/30/0/threaded");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "7.1.0", test_version2: "7.1.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2.0", test_version2: "7.2.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
