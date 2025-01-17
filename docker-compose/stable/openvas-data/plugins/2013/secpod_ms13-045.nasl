# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:microsoft:windows_essentials";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903210");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-0096");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-05-15 16:30:40 +0530 (Wed, 15 May 2013)");
  script_name("Windows Essentials Information Disclosure Vulnerability (2813707)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2813707");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-045");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_windows_live_essentials_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Windows/Essentials6432/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to overwrite arbitrary files and
  could led to launch further attacks.");

  script_tag(name:"affected", value:"Microsoft Windows Essentials 2012 and prior.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of user-supplied input processed
  by the Windows Writer component.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-045.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
winVer = infos['version'];
winLoc = infos['location'];
if(!winLoc || "Could not find the install location" >< winLoc){
  exit(0);
}

exeVer = fetch_file_version(sysPath:winLoc, file_name:"Installer\wlarp.exe");
if(exeVer) {
  if(version_is_less(version:exeVer, test_version:"16.4.3508.205")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
