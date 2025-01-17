###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Local Security Vulnerability - Nov16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809712");
  script_version("2021-05-10T09:07:58+0000");
  script_cve_id("CVE-2016-5601");
  script_bugtraq_id(93704);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2016-11-02 16:34:01 +0530 (Wed, 02 Nov 2016)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Oracle WebLogic Server Local Security Vulnerability - Nov16");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to a local security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error in the CIE Related Components within Oracle WebLogic Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker in unauthorized creation, deletion or modification access to
  critical data or all Oracle WebLogic Server accessible data as well as
  unauthorized read access to a subset of Oracle WebLogic Server accessible data.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 12.1.3.0, 12.2.1.0, and 12.2.1.1.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:version, test_version:"12.1.3.0.0") ||
   version_is_equal(version:version, test_version:"12.2.1.0.0") ||
   version_is_equal(version:version, test_version:"12.2.1.1.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
