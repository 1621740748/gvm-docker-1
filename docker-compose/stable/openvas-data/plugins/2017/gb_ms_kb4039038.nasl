###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Information Disclosure Vulnerability (KB4039038)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811666");
  script_version("2020-06-04T12:11:49+0000");
  script_cve_id("CVE-2017-8710");
  script_bugtraq_id(100793);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2017-09-13 09:16:59 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Information Disclosure Vulnerability (KB4039038)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4039038");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the Microsoft
  Common Console Document which improperly parses XML input containing a reference
  to an external entity.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read arbitrary files via an XML external entity (XXE) declaration.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4039038");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"mmc.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.6002.19858")){
  Vulnerable_range = "Less than 6.0.6002.19858";
}
else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24179")){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24179";
}

if(Vulnerable_range)
{
  report = 'File checked:     ' + sysPath + "\mmc.exe" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
