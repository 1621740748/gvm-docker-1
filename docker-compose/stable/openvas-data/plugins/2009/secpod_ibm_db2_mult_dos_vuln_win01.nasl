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
  script_oid("1.3.6.1.4.1.25623.1.0.900673");
  script_version("2020-03-13T10:05:38+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-1905", "CVE-2009-1906");
  script_bugtraq_id(35171);

  script_name("IBM Db2 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35235");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50909");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ38874");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker bypass security restrictions,
  cause a denial of service or gain elevated privileges.");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpack 17, 9.1 prior to Fixpack 7 and 9.5 prior to Fixpack 4.");

  script_tag(name:"insight", value:"The flaws are due to,

  - An error in DRDA Services component that can be exploited via an IPv6 address
    in the correlation token in the APPID string.

  - An unspecified error can be exploited to connect to DB2 databases without
    a valid password if ldap-based authentication is used and the LDAP server
    allows anonymous binds.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpack 17, 9.1 Fixpack 7, 9.5 Fixpack 4 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

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

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.6a")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.7");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.302.513")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.400.576");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
