###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Multiple Unspecified Vulnerabilities -01 May16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807566");
  script_version("2021-05-10T09:07:58+0000");
  script_cve_id("CVE-2016-0638", "CVE-2016-3416", "CVE-2016-0675", "CVE-2016-0700",
                "CVE-2016-0688", "CVE-2016-0696", "CVE-2014-4217", "CVE-2013-5855",
                "CVE-2014-2481", "CVE-2014-2480", "CVE-2014-2479", "CVE-2014-4267",
                "CVE-2014-4256", "CVE-2014-4202", "CVE-2014-4253", "CVE-2014-4242",
                "CVE-2014-4255", "CVE-2014-4254", "CVE-2014-4201", "CVE-2014-4210",
                "CVE-2014-2470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2016-05-03 17:27:14 +0530 (Tue, 03 May 2016)");

  script_name("Oracle WebLogic Server Multiple Unspecified Vulnerabilities -01 May16");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified vulnerabilities in Oracle Fusion Middleware.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to have an impact on
  confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0, 12.1.2.0, 12.1.3.0, 12.1.1.0,
  12.2.1.0 and 10.0.2.0.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:version, test_version:"10.3.6.0.0") ||
   version_is_equal(version:version, test_version:"12.1.2.0.0") ||
   version_is_equal(version:version, test_version:"12.1.3.0.0") ||
   version_is_equal(version:version, test_version:"12.2.1.0.0") ||
   version_is_equal(version:version, test_version:"12.1.1.0.0") ||
   version_is_equal(version:version, test_version:"10.0.2.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
