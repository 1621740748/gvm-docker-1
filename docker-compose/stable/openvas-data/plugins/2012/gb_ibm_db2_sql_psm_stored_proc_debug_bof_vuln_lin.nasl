###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 SQL/PSM Stored Procedure Debugging Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803107");
  script_version("2020-03-12T10:08:50+0000");
  script_tag(name:"last_modification", value:"2020-03-12 10:08:50 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"creation_date", value:"2012-10-25 11:58:30 +0530 (Thu, 25 Oct 2012)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2012-4826");
  script_bugtraq_id(56133);

  script_name("IBM Db2 SQL/PSM Stored Procedure Debugging Buffer Overflow Vulnerability (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50921/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78817");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21614536");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033685");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007053");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code.");

  script_tag(name:"insight", value:"The Stored Procedure (SP) infrastructure fails to properly sanitize
  user-supplied input when debugging stored procedures, which will result in a stack-based buffer overflow.");

  script_tag(name:"summary", value:"IBM Db2 is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.7 FP7 or later.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.1, 9.5, 9.7 before FP7, 9.8 and 10.1 on Linux");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033685");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.12");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.10");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.8.0.0", test_version2: "9.8.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.0", test_version2: "10.1.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
