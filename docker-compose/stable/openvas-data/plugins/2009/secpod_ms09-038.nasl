###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows AVI Media File Parsing Vulnerabilities (971557)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-30
#     - To detect file version 'avifil32.dll' on vista and win 2008
#
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900907");
  script_version("2020-12-08T12:38:13+0000");
  script_tag(name:"last_modification", value:"2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1545", "CVE-2009-1546");
  script_bugtraq_id(35967, 35970);
  script_name("Microsoft Windows AVI Media File Parsing Vulnerabilities (971557)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/971557");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-038");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Attackers can exploit this issue via maliciously crafted AVI files to cause
  integer overflow, execute arbitrary code with the privileges of the affected
  user and may cause denial of service.");

  script_tag(name:"affected", value:"- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");

  script_tag(name:"insight", value:"This vulnerability arises due to flaws in the way Microsoft Windows handles
  Audio Video Interleave (AVI) files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-038.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-038 Hotfix (971557)
if(hotfix_missing(name:"971557") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"avifil32.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:dllVer, test_version:"5.0", test_version2:"5.0.2195.7315")) {
    report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"5.0 - 5.0.2195.7315", install_path:sysPath);
    security_message(port: 0, data: report);
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.1", test_version2:"5.1.2600.3584")) {
      report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"5.1 - 5.1.2600.3584", install_path:sysPath);
      security_message(port: 0, data: report);
    }
      exit(0);
  }

  else if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.1", test_version2:"5.1.2600.5826")) {
      report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"5.1 - 5.1.2600.5826", install_path:sysPath);
      security_message(port: 0, data: report);
    }
      exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:dllVer, test_version:"5.2", test_version2:"5.2.3790.4526")) {
      report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"5.2 - 5.2.3790.4526", install_path:sysPath);
      security_message(port: 0, data: report);
    }
      exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"avifil32.dll");
  if(!dllVer){
    exit(0);
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18270")) {
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18270", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18049")) {
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18049", install_path:sysPath);
        security_message(port: 0, data: report);
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18270")) {
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18270", install_path:sysPath);
      security_message(port: 0, data: report);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18049")) {
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18049", install_path:sysPath);
        security_message(port: 0, data: report);
    }
     exit(0);
  }
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

