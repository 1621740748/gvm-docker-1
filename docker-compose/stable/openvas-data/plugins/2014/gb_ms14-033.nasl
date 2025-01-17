###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Window XML Core Services Information Disclosure Vulnerability (2966061)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804635");
  script_version("2019-12-20T10:24:46+0000");
  script_cve_id("CVE-2014-1816");
  script_bugtraq_id(67895);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2014-06-11 08:45:39 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Window XML Core Services Information Disclosure Vulnerability (2966061)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS14-033.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an error when parsing XML entities that is triggered
when handling specially crafted XML content on a webpage.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose sensitive
information.");
  script_tag(name:"affected", value:"- Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2939576");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957482");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2966631");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms14-033");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3, win7:2, win7x64:2,
                   win2008:3, win2008x64:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3.dll");

if(dllVer3)
{
  if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.100.1055.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.100.5008.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_in_range(version:dllVer3, test_version:"8.110.7601.18000", test_version2:"8.110.7601.18430") ||
       version_in_range(version:dllVer3, test_version:"8.110.7601.22000", test_version2:"8.110.7601.22639")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win8x64:1, win2012:1) > 0)
  {
    if(version_in_range(version:dllVer3, test_version:"8.110.9200.16000", test_version2:"8.110.9200.16862") ||
       version_in_range(version:dllVer3, test_version:"8.110.9200.20000", test_version2:"8.110.9200.20981")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  ## Currently not supporting for Windows Server 2012 R2
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    if(version_in_range(version:dllVer3, test_version:"8.110.9200.16800", test_version2:"8.110.9200.16862") ||
       version_in_range(version:dllVer3, test_version:"8.110.9200.20000", test_version2:"8.110.9200.20981") ||
       version_in_range(version:dllVer3, test_version:"8.110.9600.16000", test_version2:"8.110.9600.16662")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3r.dll");

if(dllVer4)
{
  if(hotfix_check_sp(win8:1) > 0)
  {
    dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3r.dll");

    if(version_is_less(version:dllVer4, test_version:"8.110.9600.16384")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}


dllVer6 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml6.dll");

if(dllVer6)
{
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.5007.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.30.7601.18431") ||
      version_in_range(version:dllVer6, test_version:"6.30.7601.22000", test_version2:"6.30.7601.22639")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.2017.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
