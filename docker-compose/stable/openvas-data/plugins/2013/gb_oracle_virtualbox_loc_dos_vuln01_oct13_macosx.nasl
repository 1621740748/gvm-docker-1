###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VM VirtualBox Local Denial of Service Vulnerability-01 Oct2013 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804122");
  script_version("2020-05-12T13:57:17+0000");
  script_cve_id("CVE-2013-3792");
  script_bugtraq_id(60794);
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)");
  script_tag(name:"creation_date", value:"2013-10-28 09:51:57 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle VM VirtualBox Local Denial of Service Vulnerability-01 Oct2013 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors related to 'core' component");

  script_tag(name:"affected", value:"Oracle VM VirtualBox version 3.2.18 and before, 4.0.20 and before, 4.1.28
  and before, 4.2.18 and before on Mac OS X");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to affect availability
  and cause local denial of service.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60794");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:oracle:vm_virtualbox", "cpe:/a:sun:virtualbox");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.17")||
   version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.19")||
   version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.27")||
   version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.17")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
