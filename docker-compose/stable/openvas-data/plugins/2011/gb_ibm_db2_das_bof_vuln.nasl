###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Administration Server (DAS) Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801589");
  script_version("2020-04-17T03:30:22+0000");
  script_tag(name:"last_modification", value:"2020-04-17 03:30:22 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(46052);
  script_cve_id("CVE-2011-0731");

  script_name("IBM Db2 Administration Server (DAS) Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43059");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC72029");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC72028");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote users to cause denial of service or
  execution of arbitrary code.");

  script_tag(name:"affected", value:"IBM Db2 version 9.1 before FP10, version 9.5 before FP7 and version 9.7
  before FP3.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in the 'receiveDASMessage()' function in
  'db2dasrrm' and can be exploited to cause a heap-based buffer overflow via a specially crafted request sent to
  TCP port 524.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.1 FP10, 9.5 FP7, 9.7 FP3 or later.");

  script_tag(name:"summary", value:"The host is running IBM Db2 and is prone to buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0", test_version2: "9.5.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0", test_version2: "9.1.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
