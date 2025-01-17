###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 UDB Multiple Unspecified Vulnerabilities (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.901083");
  script_version("2020-03-13T10:05:38+0000");
  script_tag(name:"last_modification", value:"2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-4328", "CVE-2009-4329", "CVE-2009-4330", "CVE-2009-4333",
                "CVE-2009-4335", "CVE-2009-4439");
  script_bugtraq_id(37332);

  script_name("IBM Db2 UDB Multiple Unspecified Vulnerabilities (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37759");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3520");
  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service.");

  script_tag(name:"affected", value:"IBM DB2 version 9.5 prior to Fixpack 5.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An unspecified error in the Engine Utilities component, causes segmentation
    fault by modifying the db2ra data stream sent in a request from the load utility.

  - An unspecified error in 'db2licm' within the Engine Utilities component it
    has unknown impact and local attack vectors.

  - An unspecified error in the DRDA Services componenta, causes the server trap
    by calling a SQL stored procedure in unknown circumstances.

  - An error in relational data services component, allows attackers to obtain
    the password argument from the SET ENCRYPTION PASSWORD statement via vectors
    involving the GET SNAPSHOT FOR DYNAMIC SQL command.

  - Multiple unspecified errors in bundled stored procedures in the Spatial
    Extender component, have unknown impact and remote attack vectors.

  - An unspecified vulnerability in the Query Compiler, Rewrite, and Optimizer
    component, allows to cause a denial of service (instance crash) by compiling a SQL query");

  script_tag(name:"solution", value:"Update IBM Db2 9.5 Fixpack 5.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.5");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
