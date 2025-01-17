###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer mshtml.dll Remote Memory Corruption Vulnerability (942615)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801707");
  script_version("2020-06-09T10:15:40+0000");
  script_tag(name:"last_modification", value:"2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3902", "CVE-2007-3903", "CVE-2007-5344", "CVE-2007-5347");
  script_bugtraq_id(26506, 26816, 26817, 26427);
  script_name("Microsoft Internet Explorer mshtml.dll Remote Memory Corruption Vulnerability (942615)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Dec/1019078.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-069");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code with
  the privileges of the application. Failed attacks may cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x.");

  script_tag(name:"insight", value:"The flaws are due to

  - A use-after-free error in mshtml.dll when handling 'setExpression()' method calls.

  - An error within the handling of the 'cloneNode()' and 'nodeValue()' methods.

  - An error when handling document objects that have been created, modified,
    deleted, and are then accessed.

  - An error when displaying web pages containing certain unexpected method calls.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-069.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS07-069 Hotfix (942615)
if(hotfix_missing(name:"942615") == 0){
    exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3858.1099"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3242") ||
           version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16586")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }

   else if(hotfix_check_sp(win2003:3) > 0)
   {
     SP = get_kb_item("SMB/Win2003/ServicePack");
     if("Service Pack 1" >< SP)
     {
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.3040")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
       exit(0);
     }

     else if("Service Pack 2" >< SP)
     {
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4185") ||
          version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16586")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
       exit(0);
     }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\mshtml.dll");
if(dllVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6000.16586")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
       exit(0);
  }
}
