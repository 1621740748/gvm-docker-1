###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Secure Kernel Mode Privilege Elevation Vulnerability (3205642)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810236");
  script_version("2019-12-20T10:24:46+0000");
  script_cve_id("CVE-2016-7271");
  script_bugtraq_id(94734);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-12-14 08:20:30 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Secure Kernel Mode Privilege Elevation Vulnerability (3205642)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-150.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the windows secure kernel
  mode fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a locally
  authenticated attacker to violate virtual trust levels (VTL).");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2016

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3205642");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-150");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-150");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

if(!egdeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll")){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  if(version_is_less(version:egdeVer, test_version:"11.0.10240.17202"))
  {
    Vulnerable_range = "Less than 11.0.10240.17202";
    VULN = TRUE ;
  }
  else if(version_in_range(version:egdeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.712"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.712";
    VULN = TRUE ;
  }
  else if(version_in_range(version:egdeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.575"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.575";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + egdeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
