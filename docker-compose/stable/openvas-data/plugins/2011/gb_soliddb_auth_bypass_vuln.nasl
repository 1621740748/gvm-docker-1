###############################################################################
# OpenVAS Vulnerability Test
#
# IBM solidDB User Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:soliddb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801938");
  script_version("2020-11-12T05:31:02+0000");
  script_tag(name:"last_modification", value:"2020-11-12 05:31:02 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1560");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM solidDB User Authentication Bypass Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66455");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21474552");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_mandatory_keys("IBM-soliddb/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass authentication.");
  script_tag(name:"affected", value:"IBM solidDB version before 4.5.181, 6.0.x before 6.0.1067,
  6.1.x and 6.3.x before 6.3.47, and 6.5.x before 6.5.0.3");
  script_tag(name:"insight", value:"The flaw exists within the 'solid.exe' process which listens by default on
  TCP ports 1315, 1964 and 2315. The authentication protocol allows a remote
  attacker to specify the length of a password hash. An attacker could bypass
  the authentication by specifying short length value.");
  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running IBM solidDB and is prone to authentication bypass
  vulnerability.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

version = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9.]+)", string: ver);
if(version[1] != NULL)
  ver = version[1];

if(version_is_less(version:ver, test_version:"4.5.181")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.5.181");
  security_message(port: port, data: report);
  exit(0);
}

if(ver =~ "^6\.0\.*") {
  if(version_is_less(version:ver, test_version:"6.0.1067")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.0.1067");
    security_message(port: port, data: report);
    exit(0);
  }
}

if(ver =~ "^6\.1\.*") {
  security_message(port:port);
  exit(0);
}

if(ver =~ "^06\.3.*") {
  if(version_is_less(version:ver, test_version:"06.30.0047")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"06.30.0047");
    security_message(port: port, data: report);
    exit(0);
  }
}

if(ver =~ "^6\.5\.*") {
  if(version_is_less(version:ver, test_version:"6.5.0.3")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.5.0.3");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
