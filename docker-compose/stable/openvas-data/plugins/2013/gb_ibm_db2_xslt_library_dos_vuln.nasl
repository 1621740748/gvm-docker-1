###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 XSLT Library Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803789");
  script_version("2020-03-13T07:09:19+0000");
  script_tag(name:"last_modification", value:"2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2013-12-26 17:51:52 +0530 (Thu, 26 Dec 2013)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2013-5466");
  script_bugtraq_id(64334);

  script_name("IBM Db2 XSLT Library Denial of Service Vulnerability");

  script_tag(name:"summary", value:"IBM Db2 is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The fix for this vulnerability is available for download for Db2 V9.7 FP9

  For Db2 V9.5, V9.8, V10.1 and V10.5, the fix is planned to be made available in future fix packs.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Flaw is due to a NULL pointer dereference error within the XLST library.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.5 through FP9, 9.7 through FP9, 9.8 through FP5,
  10.1 through FP3 and 10.5 through FP2");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause denial of service conditions.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56012");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88365");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21660046");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.8.0.0", test_version2: "9.8.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.0", test_version2: "10.1.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0.0", test_version2: "10.5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
