###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Schannel Security Feature Bypass Vulnerability (3046049)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805490");
  script_version("2020-11-12T09:56:04+0000");
  script_cve_id("CVE-2015-1637");
  script_bugtraq_id(72965);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2015-03-11 11:44:31 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Schannel Security Feature Bypass Vulnerability (3046049)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-031.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in schannel
  which does not properly restrict TLS state transitions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to conduct cipher-downgrade attacks to EXPORT_RSA ciphers via
  crafted TLS traffic.");

  script_tag(name:"affected", value:"- Microsoft Windows 2003 x32/x64 Service Pack 2

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32 Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows Server 2008 x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3046049");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-031");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3,
                   win2008r2:2, win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\schannel.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5564")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19332") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"7.0.6002.23639")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18779") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22982")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17293") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21409")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17702")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
