###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Self Tuning Memory Manager (STMM) DOS Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com> on 2009/12/29 #6444
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901079");
  script_version("2020-03-13T10:05:38+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4334", "CVE-2009-4438");
  script_bugtraq_id(37332);

  script_name("IBM Db2 Self Tuning Memory Manager (STMM) DOS Vulnerability (Linux)");

  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v97/APARLIST.TXT");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v91/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service
  or have other impact by writing to this file.");

  script_tag(name:"affected", value:"IBM Db2 version 9.1 prior to FP8, 9.5 prior to FP5 and 9.7 prior to FP1");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in Self Tuning Memory Manager (STMM) component when 0666
    permissions for the STMM log file  is used.

  - An error in Query Compiler, Rewrite, and Optimizer component does not enforce
    privilege requirements for access to a 'sequence' or 'global-variable' object,
    which allows remote users to make use of data via unspecified vectors.");

  script_tag(name:"solution", value:"Update IBM Db2 9.1 FP8, 9.5 FP5, 9.7 FP1 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to a denial of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.8");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.5");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.7.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.1");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
