###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 Multiple DOS Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900677");
  script_version("2020-03-13T10:05:38+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-6821", "CVE-2008-6820", "CVE-2008-2154");
  script_bugtraq_id(31058, 35409);

  script_name("IBM Db2 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022319.htm");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service or gain elevated privileges.");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpack 17, 9.1 prior to Fixpack 5 and
  9.5 prior to Fixpack 2");

  script_tag(name:"insight", value:"The flaws are due to,

  - An unspecified error related to the DB2FMP process running
    with OS prvileges.

  - An error in INSTALL_JAR procedure  might allows remote authenticated
    users to create or overwrite arbitrary files via unspecified calls.

  - A boundary error in DAS server code can be exploited to cause a buffer
    overflow via via unspecified vectors.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpakk 17, 9.1 Fixpack 5, 9.5 Fixpack 2 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ibm:db2";

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.17");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.401.444")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.500.555");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.100.179")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.200.315");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
