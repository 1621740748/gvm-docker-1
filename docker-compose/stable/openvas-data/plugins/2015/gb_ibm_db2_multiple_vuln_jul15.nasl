###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Multiple Vulnerabilities - July15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805940");
  script_version("2020-03-13T07:09:19+0000");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2015-07-29 14:18:25 +0530 (Wed, 29 Jul 2015)");

  script_cve_id("CVE-2015-1935", "CVE-2015-1922", "CVE-2015-1883", "CVE-2015-0157", "CVE-2014-8910");
  script_bugtraq_id(75908, 75911, 75946, 75947, 75949);

  script_name("IBM DB2 Multiple Vulnerabilities - July15");

  script_tag(name:"summary", value:"IBM DB2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the scalar-function implementation.

  - An error in the Data Movement implementation.

  - An error allowing crafted use of an automated-maintenance policy stored
    procedure to read certain administrative files.

  - An unspecified error in an unspecified scalar function.

  - An error allowing crafted XML/XSLT function in a SELECT statement to read arbitrary text files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to bypass security restrictions, gain access to sensitive data and cause the
  server to terminate abnormally causing a denial of service or potentially execute arbitrary code.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.7 through FP10, 9.8 through FP5, 10.1 before FP5 and
  10.5 through FP5.");

  script_tag(name:"solution", value:"Apply the appropriate fix from the referenced advisories.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21697988");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21697987");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21698308");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21959650");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21902661");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.8.0.0", test_version2: "9.8.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}


if (version_in_range(version: version, test_version: "10.1.0.0", test_version2: "10.1.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}


if (version_in_range(version: version, test_version: "10.5.0.0", test_version2: "10.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}


exit(99);
