# Copyright (C) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901228");
  script_version("2021-08-04T10:08:11+0000");
  script_cve_id("CVE-2014-0254");
  script_bugtraq_id(65409);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2014-02-12 09:23:09 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Windows IPv6 Denial of Service Vulnerability (2904659)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS14-006.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to incomplete validation of TCP/IP network packets.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
condition.");
  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2904659");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-006");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\tcpip.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16754") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20866")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
