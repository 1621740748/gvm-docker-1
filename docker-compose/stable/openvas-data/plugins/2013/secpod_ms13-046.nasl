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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903208");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-1332", "CVE-2013-1333", "CVE-2013-1334");
  script_bugtraq_id(59782, 59749, 59750);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-05-15 10:20:25 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2840221)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2829361");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2830290");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53385");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-046");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain escalated
  privileges or cause buffer overflow and execute arbitrary code.");
  script_tag(name:"affected", value:"- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A race condition error within the DirectX graphics kernel subsystem.

  - An unspecified error within the Windows kernel-mode driver (win32k.sys)");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-046.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

winSysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
ntosVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Ntoskrnl.exe");
DxgVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Dxgkrnl.sys");
if(winSysVer ||  ntosVer || DxgVer)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:winSysVer, test_version:"5.1.2600.6379")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:winSysVer, test_version:"5.2.3790.5148")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:winSysVer, test_version:"6.0.6002.18817") ||
       version_in_range(version:winSysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23093") ||
       version_is_less(version:DxgVer, test_version:"7.0.6002.18822") ||
       version_in_range(version:DxgVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23094")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_in_range(version:winSysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18125")||
       version_in_range(version:winSysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22295")||
       version_in_range(version:DxgVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18125")||
       version_in_range(version:DxgVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22295")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    if(version_is_less(version:ntosVer, test_version:"6.2.9200.16581") ||
       version_in_range(version:ntosVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20684")||
       version_in_range(version:DxgVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16582")||
       version_in_range(version:DxgVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20686")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
