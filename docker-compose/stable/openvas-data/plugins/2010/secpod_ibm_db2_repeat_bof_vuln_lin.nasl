###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Db2 REPEAT Buffer Overflow and TLS Renegotiation Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902174");
  script_version("2020-03-13T07:09:19+0000");
  script_tag(name:"last_modification", value:"2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2010-1560");

  script_name("IBM Db2 REPEAT Buffer Overflow and TLS Renegotiation Vulnerabilities (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39500");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0982");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21426108");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65922");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service or
  to bypass security restrictions.");

  script_tag(name:"affected", value:"IBM Db2 version 9.1 prior to FP9.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Buffer overflow error within the scalar function 'REPEAT', which could allow
    malicious users to cause a vulnerable server to crash.

  - An error in the 'TLS' implementation while handling session 're-negotiations'
    which can be exploited to insert arbitrary plaintext into an existing TLS
    session via Man-in-the-Middle (MitM) attacks.");

  script_tag(name:"solution", value:"Update IBM Db2 9.1 FP9.");

  script_tag(name:"summary", value:"IBM DB2 is prone to a buffer overflow and TLS renegotiation vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
